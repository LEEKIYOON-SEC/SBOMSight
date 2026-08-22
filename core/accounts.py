"""계정과 세션.

이 도구가 다루는 것은 어느 서버에 어떤 취약점이 열려 있는가다. 그 목록은
공격자에게 그대로 지도가 되므로, 내부망에 띄운다고 해서 아무나 열어 볼 수 있게
두면 안 된다.

표준 라이브러리만 쓴다. 폐쇄망 PC 한 대에 pip 로 추가 패키지를 들이는 것 자체가
운영 부담이고, 비밀번호 해싱과 토큰 생성에 필요한 것은 파이썬에 이미 다 있다.

- 비밀번호: `hashlib.scrypt` (메모리 하드 KDF). bcrypt·argon2 는 외부 패키지다.
- 세션 토큰: `secrets.token_urlsafe(32)` = 256비트 난수.
- 비교: `secrets.compare_digest` (타이밍 비교)

저장은 스캔 결과와 같은 SQLite 파일을 쓴다. 파일이 하나여야 백업과 이전이 쉽고,
계정만 따로 남거나 사라지는 일이 없다.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

ADMIN = "admin"
VIEWER = "viewer"
ROLES = (ADMIN, VIEWER)

# scrypt 파라미터. n=16384·r=8·p=1 은 한 번 계산에 16MB 를 쓴다 — 로그인 한 번에는
# 대수롭지 않고, 해시 목록이 유출됐을 때 대입 공격에는 충분히 성가시다.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_SALT_BYTES = 16
_KEY_BYTES = 32

SESSION_TTL_HOURS = 12
MIN_PASSWORD_LEN = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    pw_hash       TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
"""


class AccountError(ValueError):
    """운영자에게 그대로 보여 줄 수 있는 실패 사유."""


@dataclass(frozen=True)
class User:
    username: str
    role: str
    created_at: str
    last_login_at: str = ""

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN

    def to_dict(self) -> dict[str, str]:
        return {
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }


@dataclass(frozen=True)
class Session:
    token: str
    username: str
    role: str
    expires_at: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    """`scrypt$n$r$p$salt$key` 형태로 저장한다.

    파라미터를 해시와 함께 남겨야 나중에 강도를 올려도 기존 해시를 계속 검증할 수
    있다. 파라미터를 코드에만 두면 값을 바꾸는 순간 전원이 로그인하지 못한다.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    key = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, maxmem=_SCRYPT_MAXMEM, dklen=_KEY_BYTES,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, key_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        key = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), maxmem=_SCRYPT_MAXMEM, dklen=len(key_hex) // 2,
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(key.hex(), key_hex)


def check_username(username: str) -> str:
    """영문·숫자와 `- _ .` 만 허용한다.

    `str.isalnum()` 은 한글도 참으로 본다. 로그인 이름에 한글을 허용하면
    비슷하게 생긴 유니코드 문자로 다른 사람 행세를 할 여지가 생기고, 셸에서
    `core.cli user` 로 다룰 때도 성가시다. ASCII 로 제한한다.
    """
    name = (username or "").strip()
    if not 2 <= len(name) <= 32:
        raise AccountError("계정 이름은 2~32자여야 합니다.")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not set(name) <= allowed:
        raise AccountError("계정 이름에는 영문·숫자와 - _ . 만 쓸 수 있습니다.")
    return name


def check_password(password: str) -> str:
    if len(password or "") < MIN_PASSWORD_LEN:
        raise AccountError(f"비밀번호는 {MIN_PASSWORD_LEN}자 이상이어야 합니다.")
    return password


def check_role(role: str) -> str:
    if role not in ROLES:
        raise AccountError(f"권한은 {' 또는 '.join(ROLES)} 여야 합니다.")
    return role


class Accounts:
    """계정·세션 저장소. 스캔 결과와 같은 DB 파일을 쓴다."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- 계정 -------------------------------------------------------------

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])

    def list_users(self) -> list[User]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, role, created_at, last_login_at FROM users ORDER BY username"
            ).fetchall()
        return [User(**dict(r)) for r in rows]

    def get(self, username: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, role, created_at, last_login_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return User(**dict(row)) if row else None

    def create(self, username: str, password: str, role: str = VIEWER) -> User:
        name = check_username(username)
        check_password(password)
        check_role(role)
        user = User(username=name, role=role, created_at=_now())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users (username, pw_hash, role, created_at, last_login_at) "
                    "VALUES (?,?,?,?,'')",
                    (name, hash_password(password), role, user.created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise AccountError(f"'{name}' 계정이 이미 있습니다.") from exc
        return user

    def set_password(self, username: str, password: str) -> None:
        check_password(password)
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE users SET pw_hash = ? WHERE username = ?",
                (hash_password(password), username),
            ).rowcount
            if not changed:
                raise AccountError(f"'{username}' 계정이 없습니다.")
            # 비밀번호를 바꾸면 기존 세션은 전부 끊는다. 유출을 의심해 바꾸는
            # 경우가 대부분인데 예전 세션이 살아 있으면 바꾼 의미가 없다.
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def set_role(self, username: str, role: str) -> None:
        check_role(role)
        with self._connect() as conn:
            if role != ADMIN and self._last_admin(conn, username):
                raise AccountError("마지막 관리자의 권한은 내릴 수 없습니다.")
            changed = conn.execute(
                "UPDATE users SET role = ? WHERE username = ?", (role, username)
            ).rowcount
        if not changed:
            raise AccountError(f"'{username}' 계정이 없습니다.")

    def delete(self, username: str) -> None:
        with self._connect() as conn:
            if self._last_admin(conn, username):
                raise AccountError("마지막 관리자는 삭제할 수 없습니다. 먼저 다른 관리자를 만드세요.")
            changed = conn.execute("DELETE FROM users WHERE username = ?", (username,)).rowcount
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        if not changed:
            raise AccountError(f"'{username}' 계정이 없습니다.")

    @staticmethod
    def _last_admin(conn: sqlite3.Connection, username: str) -> bool:
        """이 계정을 지우거나 강등하면 관리자가 한 명도 없게 되는가.

        관리자가 사라지면 웹에서 계정을 만들 수도 지울 수도 없다. CLI 로 되살릴
        수는 있지만, 실수 한 번에 그 지경까지 갈 이유가 없다.
        """
        row = conn.execute(
            "SELECT role FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None or row["role"] != ADMIN:
            return False
        others = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = ? AND username != ?", (ADMIN, username)
        ).fetchone()["n"]
        return not others

    # --- 인증 -------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, pw_hash, role, created_at, last_login_at FROM users "
                "WHERE username = ?",
                (username,),
            ).fetchone()

        if row is None:
            # 계정이 없어도 해시 한 번을 계산한다. 응답 시간만으로 "그 계정은
            # 존재한다"를 알아낼 수 없게 하기 위함이다.
            verify_password(password, hash_password("_"))
            return None
        if not verify_password(password, row["pw_hash"]):
            return None
        return User(
            username=row["username"], role=row["role"],
            created_at=row["created_at"], last_login_at=row["last_login_at"],
        )

    # --- 세션 -------------------------------------------------------------

    def open_session(self, username: str, *, ttl_hours: int = SESSION_TTL_HOURS) -> Session:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=ttl_hours)).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?,?,?,?)",
                (token, username, now.isoformat(timespec="seconds"), expires),
            )
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE username = ?",
                (now.isoformat(timespec="seconds"), username),
            )
            role = conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()["role"]
        return Session(token=token, username=username, role=role, expires_at=expires)

    def resolve(self, token: str) -> Session | None:
        """토큰으로 세션을 찾는다. 만료된 것은 그 자리에서 지운다."""
        if not token:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT s.token, s.username, s.expires_at, u.role FROM sessions s "
                "JOIN users u ON u.username = s.username WHERE s.token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= _now():
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return None
        return Session(
            token=row["token"], username=row["username"],
            role=row["role"], expires_at=row["expires_at"],
        )

    def close_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def purge_expired(self) -> int:
        with self._connect() as conn:
            return conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_now(),)).rowcount
