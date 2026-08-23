"""자산(서버) 모델과 스캔 이력.

이 도구의 관리 단위는 "스캔"이 아니라 **서버 한 대**다. `web-01` 의 SBOM 을 매달
올리고, 지난달 대비 무엇이 새로 생기고 무엇이 사라졌는지를 보는 것이 실제 운영이다.
"최근 스캔 목록"으로는 그 질문에 답할 수 없다.

담당자 필드는 두지 않는다. 업무분장에 따라 바뀌는 것은 자산의 속성이 아니다.

이력 비교의 축은 `(cve, 설치 패키지명)` 이다. `Finding.key` 는 설치 버전을
포함하므로 패치하면 키가 바뀐다 — 그것으로 비교하면 "패치했더니 취약점이 하나
사라지고 하나 새로 생겼다"는 엉뚱한 답이 나온다.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

UNASSIGNED = ""  # 자산에 배정되지 않은 스캔 (자산 개념 이전에 만들어진 것들)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    group_name  TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    archived_at TEXT NOT NULL DEFAULT ''
);
"""

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AssetError(ValueError):
    """운영자에게 그대로 보여 줄 수 있는 실패 사유."""


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    group_name: str = ""
    os: str = ""
    note: str = ""
    created_at: str = ""
    archived_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "group_name": self.group_name,
            "os": self.os,
            "note": self.note,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class Change:
    """이력 비교의 한 줄. 자산 안에만 머무는 내부 정보다."""

    cve: str
    package_name: str
    installed_version: str = ""
    previous_version: str = ""
    priority: str = ""
    fixed_version: str = ""


@dataclass(frozen=True)
class Diff:
    """두 스캔 사이에 무엇이 달라졌는가.

    세 갈래로 낸다 — 신규·해소·유지. "몇 건에서 몇 건이 됐다"만으로는 같은 수라도
    내용이 완전히 바뀐 경우를 구분할 수 없다.
    """

    base_scan_id: str
    head_scan_id: str
    added: tuple[Change, ...] = ()
    resolved: tuple[Change, ...] = ()
    remaining: tuple[Change, ...] = ()
    base_created_at: str = ""
    head_created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_scan_id": self.base_scan_id,
            "head_scan_id": self.head_scan_id,
            "base_created_at": self.base_created_at,
            "head_created_at": self.head_created_at,
            "counts": {
                "added": len(self.added),
                "resolved": len(self.resolved),
                "remaining": len(self.remaining),
            },
            "added": [vars(c) for c in self.added],
            "resolved": [vars(c) for c in self.resolved],
            "remaining": [vars(c) for c in self.remaining],
        }


def check_name(name: str) -> str:
    """호스트명처럼 쓰이므로 호스트명 규칙에 맞춘다.

    공백과 슬래시를 허용하면 URL 경로와 파일 경로 양쪽에서 성가시고, 실수로
    `web-01 ` 처럼 뒤에 공백이 붙은 별개의 자산이 생긴다.
    """
    text = (name or "").strip()
    if not text:
        raise AssetError("자산 이름을 입력하세요.")
    if not _NAME.match(text):
        raise AssetError(
            "자산 이름은 영문·숫자로 시작하고 영문·숫자와 . _ - 만 쓸 수 있습니다 (최대 64자)."
        )
    return text


def new_asset_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _change_key(finding: dict[str, Any]) -> tuple[str, str] | None:
    """비교 축 — `(cve, 설치 패키지명)`.

    설치 버전은 넣지 않는다. 넣으면 패치할 때마다 키가 바뀌어 모든 항목이
    "해소 1건 + 신규 1건"으로 갈라진다.
    """
    cve = str((finding.get("intel") or {}).get("cve") or "")
    package = str((finding.get("installed") or {}).get("name") or "")
    return (cve, package) if cve and package else None


def _to_change(finding: dict[str, Any], *, previous_version: str = "") -> Change:
    intel = finding.get("intel") or {}
    installed = finding.get("installed") or {}
    advisory = finding.get("advisory") or {}
    verdict = finding.get("verdict") or {}
    return Change(
        cve=str(intel.get("cve") or ""),
        package_name=str(installed.get("name") or ""),
        installed_version=str(installed.get("version") or ""),
        previous_version=previous_version,
        priority=str(verdict.get("priority") or ""),
        fixed_version=str(advisory.get("fixed_version") or ""),
    )


def diff_findings(
    base: list[dict[str, Any]],
    head: list[dict[str, Any]],
    *,
    base_scan_id: str = "",
    head_scan_id: str = "",
    base_created_at: str = "",
    head_created_at: str = "",
) -> Diff:
    """두 스캔의 finding 목록을 대조한다.

    `head` 기준으로 신규·유지를, `base` 기준으로 해소를 낸다. 유지 항목에는
    이전 설치 버전을 함께 담는다 — 버전이 올랐는데도 여전히 취약한 경우(부분
    패치)가 실제로 있고, 그것은 신규도 해소도 아니지만 봐야 하는 정보다.
    """
    base_index = {key: f for f in base if (key := _change_key(f))}
    head_index = {key: f for f in head if (key := _change_key(f))}

    added, remaining = [], []
    for key, finding in head_index.items():
        previous = base_index.get(key)
        if previous is None:
            added.append(_to_change(finding))
        else:
            remaining.append(
                _to_change(
                    finding,
                    previous_version=str((previous.get("installed") or {}).get("version") or ""),
                )
            )

    resolved = [_to_change(f) for key, f in base_index.items() if key not in head_index]

    def order(change: Change) -> tuple[str, str]:
        return (change.package_name, change.cve)

    return Diff(
        base_scan_id=base_scan_id,
        head_scan_id=head_scan_id,
        base_created_at=base_created_at,
        head_created_at=head_created_at,
        added=tuple(sorted(added, key=order)),
        resolved=tuple(sorted(resolved, key=order)),
        remaining=tuple(sorted(remaining, key=order)),
    )


class Assets:
    """자산 저장소. 스캔 결과와 같은 SQLite 파일을 쓴다."""

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

    # --- CRUD -------------------------------------------------------------

    def create(self, name: str, *, group_name: str = "", os: str = "", note: str = "") -> Asset:
        asset = Asset(
            asset_id=new_asset_id(),
            name=check_name(name),
            group_name=(group_name or "").strip(),
            os=(os or "").strip(),
            note=(note or "").strip(),
            created_at=_now(),
        )
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO assets (asset_id, name, group_name, os, note, created_at, archived_at) "
                    "VALUES (?,?,?,?,?,?,'')",
                    (asset.asset_id, asset.name, asset.group_name, asset.os,
                     asset.note, asset.created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise AssetError(f"'{asset.name}' 자산이 이미 있습니다.") from exc
        return asset

    def get(self, asset_id: str) -> Asset | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
        return Asset(**dict(row)) if row else None

    def by_name(self, name: str) -> Asset | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM assets WHERE name = ?", (name,)).fetchone()
        return Asset(**dict(row)) if row else None

    def list(self) -> list[Asset]:
        sql = "SELECT * FROM assets ORDER BY group_name, name"
        with self._connect() as conn:
            return [Asset(**dict(r)) for r in conn.execute(sql)]

    def update(self, asset_id: str, **fields: str) -> Asset:
        current = self.get(asset_id)
        if current is None:
            raise AssetError("자산을 찾을 수 없습니다.")

        allowed = {"name", "group_name", "os", "note"}
        changes = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if "name" in changes:
            changes["name"] = check_name(str(changes["name"]))
        for key in ("group_name", "os", "note"):
            if key in changes:
                changes[key] = str(changes[key]).strip()

        if changes:
            assignments = ", ".join(f"{k} = ?" for k in changes)
            try:
                with self._connect() as conn:
                    conn.execute(
                        f"UPDATE assets SET {assignments} WHERE asset_id = ?",
                        (*changes.values(), asset_id),
                    )
            except sqlite3.IntegrityError as exc:
                raise AssetError(f"'{changes['name']}' 자산이 이미 있습니다.") from exc

        updated = self.get(asset_id)
        assert updated is not None
        return updated

    def scan_ids(self, asset_id: str) -> list[str]:
        """이 자산에 달린 스캔 ID. 지울 것을 세고 지우는 데 쓴다."""
        with self._connect() as conn:
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
            ).fetchone():
                return []
            return [r["scan_id"] for r in conn.execute(
                "SELECT scan_id FROM scans WHERE asset_id = ?", (asset_id,)
            )]

    def delete(self, asset_id: str) -> list[str]:
        """자산을 지운다. **그 자산의 스캔도 함께 지운다.**

        자산이 사라졌는데 그 자산의 결과만 남으면 어디에도 속하지 않는 데이터가
        쌓이고, 되살릴 길도 없다. 자산을 지운다는 것은 그 서버를 더는 관리하지
        않는다는 뜻이므로 결과도 함께 정리한다.

        지운 스캔 ID 를 돌려준다. 호출부가 그것으로 디스크에 남은 산출물
        (Grype 원본 등)까지 지운다.
        """
        if self.get(asset_id) is None:
            raise AssetError("자산을 찾을 수 없습니다.")
        removed = self.scan_ids(asset_id)
        with self._connect() as conn:
            # `scans`·`findings` 는 Store 의 테이블이다. 같은 DB 파일을 쓰지만
            # Assets 만 단독으로 열 수도 있으므로, 없으면 없는 대로 지나간다.
            tables = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if removed:
                marks = ",".join("?" * len(removed))
                for table in ("findings", "narratives", "chains", "selections", "scans"):
                    if table in tables:
                        conn.execute(
                            f"DELETE FROM {table} WHERE scan_id IN ({marks})", removed
                        )
            conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
        return removed
