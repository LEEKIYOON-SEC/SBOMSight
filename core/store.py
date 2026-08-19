"""SQLite 저장소.

서버를 따로 띄울 수 없는 PC 환경이 전제라 파일 하나로 끝나는 SQLite를 쓴다.
Windows 11과 Rocky Linux 10 양쪽에서 추가 설치 없이 동작한다.

스캔 결과에는 내부 자산 정보가 들어 있으므로 이 DB 파일 자체가 내부
자산이다. .gitignore가 *.db 와 data/ 를 막고 있다.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import ScanResult, to_jsonable

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    metadata     TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id      TEXT NOT NULL,
    finding_key  TEXT NOT NULL,
    cve          TEXT NOT NULL,
    package_name TEXT NOT NULL,
    priority     TEXT,
    payload      TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve  ON findings(cve);

-- 위협정보 캐시. 오프라인에서도 마지막 스냅샷으로 동작하기 위한 것.
CREATE TABLE IF NOT EXISTS intel_cache (
    source     TEXT NOT NULL,
    key        TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (source, key)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
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

    # --- 스캔 -------------------------------------------------------------

    def save_scan(self, result: ScanResult) -> None:
        meta = to_jsonable(result.metadata)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, created_at, metadata, finding_count) VALUES (?,?,?,?)",
                (
                    result.metadata.scan_id,
                    result.metadata.created_at,
                    json.dumps(meta, ensure_ascii=False),
                    len(result.findings),
                ),
            )
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.metadata.scan_id,))
            conn.executemany(
                "INSERT INTO findings (scan_id, finding_key, cve, package_name, priority, payload) VALUES (?,?,?,?,?,?)",
                [
                    (
                        result.metadata.scan_id,
                        f.key,
                        f.intel.cve,
                        f.installed.name,
                        f.verdict.priority.value if f.verdict else None,
                        json.dumps(to_jsonable(f), ensure_ascii=False),
                    )
                    for f in result.findings
                ],
            )

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id, created_at, metadata, finding_count FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "created_at": r["created_at"],
                "finding_count": r["finding_count"],
                "metadata": json.loads(r["metadata"]),
            }
            for r in rows
        ]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = conn.execute(
                "SELECT payload FROM findings WHERE scan_id = ? ORDER BY finding_key", (scan_id,)
            ).fetchall()
        return {
            "scan_id": row["scan_id"],
            "created_at": row["created_at"],
            "metadata": json.loads(row["metadata"]),
            "findings": [json.loads(f["payload"]) for f in findings],
        }

    def delete_scan(self, scan_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))

    # --- 위협정보 캐시 -----------------------------------------------------

    def cache_put(self, source: str, key: str, payload: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO intel_cache (source, key, payload, fetched_at) VALUES (?,?,?,?)",
                (source, key, json.dumps(payload, ensure_ascii=False),
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )

    def cache_put_many(self, source: str, items: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO intel_cache (source, key, payload, fetched_at) VALUES (?,?,?,?)",
                [(source, k, json.dumps(v, ensure_ascii=False), now) for k, v in items.items()],
            )

    def cache_get(self, source: str, key: str) -> tuple[Any, str] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload, fetched_at FROM intel_cache WHERE source = ? AND key = ?", (source, key)
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"]), row["fetched_at"]

    def cache_get_many(self, source: str, keys: list[str]) -> dict[str, tuple[Any, str]]:
        if not keys:
            return {}
        placeholders = ",".join("?" * len(keys))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT key, payload, fetched_at FROM intel_cache WHERE source = ? AND key IN ({placeholders})",
                (source, *keys),
            ).fetchall()
        return {r["key"]: (json.loads(r["payload"]), r["fetched_at"]) for r in rows}

    # --- 메타 -------------------------------------------------------------

    def meta_set(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)", (key, value))

    def meta_get(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
