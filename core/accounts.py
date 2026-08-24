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
from typing import Any, Iterator

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
# 놀고 있는 세션의 수명. 자리를 비운 화면이 계속 열려 있으면, 그 화면은 "어느
# 서버에 무엇이 열려 있는가"를 그대로 보여 주는 창이다. 마지막 요청으로부터
# 이만큼 지나면 끊는다 — 절대 만료(TTL)와는 별개로 먼저 걸린다.
SESSION_IDLE_MINUTES = 10
MIN_PASSWORD_LEN = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    pw_hash       TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT NOT NULL DEFAULT '',
    -- 초기화된 계정. 다음 로그인에서 반드시 바꾸게 한다. 계정 이름과 같은
    -- 비밀번호가 그대로 남아 있으면 초기화가 곧 구멍이 된다.
    must_change   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    -- 마지막 요청 시각. 유휴 만료의 기준이다. expires_at 만 있으면 "12시간
    -- 동안 한 번도 안 쓴 세션"과 "12시간 내내 쓴 세션"을 구분할 수 없다.
    last_seen_at TEXT NOT NULL DEFAULT ''
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
    must_change: int = 0

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
            "must_change": bool(self.must_change),
        }


@dataclass(frozen=True)
class Session:
    token: str
    username: str
    role: str
    expires_at: str
    last_seen_at: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _minus(minutes: int) -> str:
    """`minutes` 분 전 시각. 이보다 오래된 `last_seen_at` 은 유휴다."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")


# 유휴 시계를 되감는 최소 간격. 화면 한 장을 여는 데 HTML·CSS·JS 모듈·API 로
# 스무 번 남짓 요청이 나가는데, 그때마다 UPDATE 를 걸면 페이지 한 장에 쓰기
# 트랜잭션이 스무 번이다. 30초 간격이면 10분 창을 재는 데 오차가 없다.
_TOUCH_SECONDS = 30


def _stale(seen: str, now: str) -> bool:
    """마지막으로 기록한 활동 시각이 `_TOUCH_SECONDS` 보다 오래됐는가."""
    if not seen:
        return True
    try:
        gap = datetime.fromisoformat(now) - datetime.fromisoformat(seen)
    except ValueError:
        return True
    return gap >= timedelta(seconds=_TOUCH_SECONDS)


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
            # 앞선 버전의 DB. 비파괴로 붙인다.
            names = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            if "must_change" not in names:
                conn.execute("ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0")

            names = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
            if "last_seen_at" not in names:
                conn.execute("ALTER TABLE sessions ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT ''")
                # 기존 세션은 마지막 요청 시각을 모른다. 시작 시각으로 채운다 —
                # 빈 값으로 두면 유휴 판정이 "아주 오래됨"이 되어 로그인한 지
                # 1분 된 사람까지 끊긴다.
                conn.execute("UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at = ''")

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
                "SELECT username, role, created_at, last_login_at, must_change "
                "FROM users ORDER BY username"
            ).fetchall()
        return [User(**dict(r)) for r in rows]

    def get(self, username: str) -> User | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, role, created_at, last_login_at, must_change "
                "FROM users WHERE username = ?",
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

    def set_password(self, username: str, password: str, *, must_change: bool = False) -> None:
        check_password(password)
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE users SET pw_hash = ?, must_change = ? WHERE username = ?",
                (hash_password(password), 1 if must_change else 0, username),
            ).rowcount
            if not changed:
                raise AccountError(f"'{username}' 계정이 없습니다.")
            # 비밀번호를 바꾸면 기존 세션은 전부 끊는다. 유출을 의심해 바꾸는
            # 경우가 대부분인데 예전 세션이 살아 있으면 바꾼 의미가 없다.
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def reset_password(self, username: str) -> str:
        """비밀번호를 **계정 이름과 같게** 되돌린다.

        담당자가 비밀번호를 잊었을 때 관리자가 새 비밀번호를 지어내 전화로
        불러 주는 것보다, 규칙이 정해져 있는 편이 안전하고 설명하기도 쉽다 —
        "아이디와 같은 비밀번호로 로그인한 뒤 바꾸세요".

        그래서 **다음 로그인에서 반드시 바꾸게 한다**(`must_change`). 그 강제가
        없으면 계정 이름과 같은 비밀번호가 그대로 남아 초기화가 곧 구멍이 된다.
        길이 규칙(8자)은 이 경로에만 적용하지 않는다. 그 값으로는 아무것도 할
        수 없고 바꾸기 전에는 화면이 열리지 않기 때문이다.
        """
        if self.get(username) is None:
            raise AccountError(f"'{username}' 계정이 없습니다.")
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET pw_hash = ?, must_change = 1 WHERE username = ?",
                (hash_password(username), username),
            )
            # 기존 세션은 전부 끊는다. 초기화한 계정이 예전 세션으로 계속
            # 돌아다니면 초기화한 의미가 없다.
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        return username

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

    def open_session(
        self,
        username: str,
        *,
        ttl_hours: int = SESSION_TTL_HOURS,
        idle_minutes: int = SESSION_IDLE_MINUTES,
    ) -> Session:
        """로그인. 이때 죽은 세션도 함께 쓸어 낸다.

        `resolve` 는 물어본 토큰 하나만 지운다. 유휴로 끊긴 세션은 아무도 다시
        묻지 않으므로 그 줄이 영영 남는다 — 유휴 만료가 10분이면 하루 몇 번의
        로그인이 그대로 쌓인다. 로그인은 드물게 일어나고 어차피 이 표에 줄을
        하나 더 넣는 자리라, 여기서 치우는 것이 가장 싸다.
        """
        self.purge_expired(idle_minutes=idle_minutes)

        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=ttl_hours)).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token, username, created_at, expires_at, last_seen_at) "
                "VALUES (?,?,?,?,?)",
                (token, username, now.isoformat(timespec="seconds"), expires,
                 now.isoformat(timespec="seconds")),
            )
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE username = ?",
                (now.isoformat(timespec="seconds"), username),
            )
            role = conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()["role"]
        return Session(token=token, username=username, role=role, expires_at=expires)

    def resolve(self, token: str, *, idle_minutes: int = SESSION_IDLE_MINUTES) -> Session | None:
        """토큰으로 세션을 찾는다. 만료된 것은 그 자리에서 지운다.

        만료는 두 가지다.

        - **절대 만료**(`expires_at`): 로그인한 지 오래됐다. 계속 쓰고 있어도 끊는다.
        - **유휴 만료**(`last_seen_at`): 마지막 요청으로부터 오래됐다. 자리를 비운
          화면을 계속 열어 두지 않기 위한 것이고, 실제로 먼저 걸리는 쪽이다.

        이 호출 자체가 곧 "요청이 하나 왔다"이므로 유휴 시계를 여기서 되감는다.
        쓰고 있는 동안 창이 밀려 나가면 안 되기 때문이다.

        `idle_minutes <= 0` 이면 유휴 만료를 걸지 않는다(절대 만료만 남는다).
        """
        if not token:
            return None
        now = _now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT s.token, s.username, s.expires_at, s.last_seen_at, u.role FROM sessions s "
                "JOIN users u ON u.username = s.username WHERE s.token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return None

            idle_cutoff = _minus(idle_minutes) if idle_minutes > 0 else ""
            seen = row["last_seen_at"] or row["expires_at"]
            if row["expires_at"] <= now or (idle_cutoff and seen <= idle_cutoff):
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return None

            if _stale(seen, now):
                conn.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE token = ?", (now, token)
                )
                seen = now

        return Session(
            token=row["token"], username=row["username"],
            role=row["role"], expires_at=row["expires_at"], last_seen_at=seen,
        )

    def close_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def purge_expired(self, *, idle_minutes: int = SESSION_IDLE_MINUTES) -> int:
        with self._connect() as conn:
            if idle_minutes > 0:
                return conn.execute(
                    "DELETE FROM sessions WHERE expires_at <= ? OR "
                    "COALESCE(NULLIF(last_seen_at, ''), expires_at) <= ?",
                    (_now(), _minus(idle_minutes)),
                ).rowcount
            return conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_now(),)).rowcount
