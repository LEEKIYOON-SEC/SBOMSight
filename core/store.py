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


def _sort_columns(payload: dict[str, Any]) -> tuple:
    """정렬·필터에 쓰는 값을 payload 에서 꺼낸다.

    `findings` 테이블의 컬럼 순서와 **정확히** 같아야 한다 —
    package_type · cvss_score · epss · fixed_version ·
    update_available · no_fix · kev · exploit.

    참(true)만 1이다. `unknown` 은 0이지만 그것은 "아니오"라는 뜻이 아니라
    "이 필터에 걸리지 않는다"는 뜻이다. 필터는 참인 것을 찾는 도구다.
    """
    intel = payload.get("intel") or {}
    installed = payload.get("installed") or {}
    advisory = payload.get("advisory") or {}
    fix = payload.get("fix") or {}
    flags = (payload.get("verdict") or {}).get("flags") or []
    return (
        str(installed.get("type") or ""),
        intel.get("cvss_score"),
        intel.get("epss"),
        str(advisory.get("fixed_version") or ""),
        1 if fix.get("update_available") == "true" else 0,
        1 if "no_fix_available" in flags else 0,
        1 if intel.get("kev") == "true" else 0,
        1 if intel.get("exploit_available") == "true" else 0,
    )


def _finding_row(scan_id: str, finding) -> tuple:
    """findings 한 행. payload 를 두 번 만들지 않도록 한 곳에서 조립한다."""
    payload = to_jsonable(finding)
    return (
        scan_id,
        finding.key,
        finding.intel.cve,
        finding.installed.name,
        finding.verdict.priority.value if finding.verdict else None,
        json.dumps(payload, ensure_ascii=False),
        *_sort_columns(payload),
    )


# 정렬 키 → SQL 식. **미확인 값은 방향과 무관하게 항상 뒤로 간다.**
#
# `x IS NULL` 을 첫 정렬 키로 두면 NULL 이 언제나 뒤에 앉는다. 데이터가 없는
# 것을 0으로 채워 줄 세우면 "악용 예측이 가장 낮은 항목" 자리에 사실은 EPSS 를
# 못 받아온 항목이 앉는다.
_SORT_SQL = {
    "priority": ("priority IS NULL", "priority", "package_name"),
    "cvss": ("cvss_score IS NULL", "cvss_score", "cve"),
    "epss": ("epss IS NULL", "epss", "cve"),
    "package": ("0", "package_name COLLATE NOCASE", "cve"),
    "cve": ("0", "cve", "package_name"),
    "fixed": ("fixed_version = ''", "fixed_version COLLATE NOCASE", "cve"),
}

_FILTER_SQL = {
    "update": "update_available = 1",
    "nofix": "no_fix = 1",
    "kev": "kev = 1",
    "exploit": "exploit = 1",
}

SORT_KEYS = tuple(_SORT_SQL)
FILTER_KEYS = tuple(_FILTER_SQL)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    metadata     TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    -- 보고서가 "어떤 데이터로, 어떤 기준으로 판정했는지"를 스스로 증명하려면
    -- 스냅샷 기준일과 정책 해시가 결과와 함께 남아 있어야 한다. 없으면
    -- 나중에 그 보고서를 재현할 수 없다.
    enrichment   TEXT NOT NULL DEFAULT '{}',
    policy       TEXT NOT NULL DEFAULT '{}'
);

-- 정렬·필터에 쓰는 값은 payload 안에만 두지 않고 **컬럼으로 꺼내 둔다.**
--
-- 서버 한 대가 48,923건을 낸다. payload JSON 을 전부 파이썬 객체로 되살려
-- 정렬하면 한 페이지를 넘기는 데 10초가 걸렸다(실측). 컬럼으로 두면 SQLite 가
-- 인덱스로 처리하고 100건분 payload 만 파싱하면 된다.
CREATE TABLE IF NOT EXISTS findings (
    scan_id      TEXT NOT NULL,
    finding_key  TEXT NOT NULL,
    cve          TEXT NOT NULL,
    package_name TEXT NOT NULL,
    priority     TEXT,
    payload      TEXT NOT NULL,
    package_type TEXT NOT NULL DEFAULT '',
    cvss_score   REAL,
    epss         REAL,
    fixed_version TEXT NOT NULL DEFAULT '',
    update_available INTEGER NOT NULL DEFAULT 0,
    no_fix       INTEGER NOT NULL DEFAULT 0,
    kev          INTEGER NOT NULL DEFAULT 0,
    exploit      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve  ON findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_sort ON findings(scan_id, priority, package_name);

-- AI가 생성한 서술. 보고서를 다시 열 때마다 모델을 또 부르지 않기 위해
-- 남긴다. 서술은 공개 데이터에서 나온 산문이므로 자산 정보를 담지 않지만,
-- 어느 스캔의 어느 CVE에 붙었는지는 내부 맥락이라 이 DB 안에만 둔다.
CREATE TABLE IF NOT EXISTS narratives (
    scan_id    TEXT NOT NULL,
    cve        TEXT NOT NULL,
    payload    TEXT NOT NULL,
    model      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, cve)
);

-- 패키지 묶음별 연계 분석. 낮은 등급 여러 건이 서로의 전제를 충족시키면
-- 파급력이 커진다는 판단을 AI가 서술한 것이다. 서술은 공개 데이터에서 나온
-- 산문이지만 어느 스캔의 어느 패키지에 붙었는지는 내부 맥락이다.
CREATE TABLE IF NOT EXISTS chains (
    scan_id    TEXT NOT NULL,
    package    TEXT NOT NULL,
    analysis   TEXT NOT NULL,
    model      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, package)
);

-- 담당자가 고른 항목. 보고서와 AI 전송의 범위이자, 나중에 "이 보고서는
-- 무엇을 대상으로 만들어졌는가"를 되짚는 근거다. 선택 키에는 설치 패키지명과
-- 설치 버전이 들어 있으므로 이 DB 밖으로 나가지 않는다.
CREATE TABLE IF NOT EXISTS selections (
    scan_id    TEXT PRIMARY KEY,
    keys       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

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
    SORT_KEYS = SORT_KEYS
    FILTER_KEYS = FILTER_KEYS

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """앞선 버전에서 만들어진 DB에 새 컬럼을 채워 넣는다.

        스캔 결과에는 내부 자산 정보가 담겨 있어 지우고 다시 만들라고 할 수
        없다. 그래서 파괴적 마이그레이션은 하지 않는다. 기존 스캔은
        `asset_id=''`(미분류)로 남고 화면에서 자산에 배정할 수 있다.
        """
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        for column in ("enrichment", "policy"):
            if column not in existing:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {column} TEXT NOT NULL DEFAULT '{{}}'")
        if "asset_id" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN asset_id TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id, created_at)")

        # 정렬·필터용 컬럼. 없던 DB 에는 붙이고 payload 에서 한 번 채운다.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        added = False
        for name, ddl in (
            ("package_type", "TEXT NOT NULL DEFAULT ''"),
            ("cvss_score", "REAL"),
            ("epss", "REAL"),
            ("fixed_version", "TEXT NOT NULL DEFAULT ''"),
            ("update_available", "INTEGER NOT NULL DEFAULT 0"),
            ("no_fix", "INTEGER NOT NULL DEFAULT 0"),
            ("kev", "INTEGER NOT NULL DEFAULT 0"),
            ("exploit", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in columns:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
                added = True
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_sort ON findings(scan_id, priority, package_name)"
        )
        if added:
            Store._backfill(conn)

    @staticmethod
    def _backfill(conn: sqlite3.Connection) -> None:
        """기존 행의 정렬용 컬럼을 payload 에서 채운다. 한 번만 돈다.

        스캔 결과를 지우고 다시 만들라고 할 수 없으므로, 이미 저장된 것도
        새 화면에서 정렬·필터가 되어야 한다.
        """
        rows = conn.execute("SELECT scan_id, finding_key, payload FROM findings").fetchall()
        updates = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError):
                continue
            values = _sort_columns(payload)
            updates.append((*values, row["scan_id"], row["finding_key"]))

        if updates:
            conn.executemany(
                "UPDATE findings SET package_type = ?, cvss_score = ?, epss = ?, "
                "fixed_version = ?, update_available = ?, no_fix = ?, kev = ?, exploit = ? "
                "WHERE scan_id = ? AND finding_key = ?",
                updates,
            )

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

    def save_scan(self, result: ScanResult, *, asset_id: str = "") -> None:
        meta = to_jsonable(result.metadata)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans "
                "(scan_id, created_at, metadata, finding_count, enrichment, policy, asset_id) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    result.metadata.scan_id,
                    result.metadata.created_at,
                    json.dumps(meta, ensure_ascii=False),
                    len(result.findings),
                    json.dumps(result.enrichment or {}, ensure_ascii=False),
                    json.dumps(result.policy or {}, ensure_ascii=False),
                    asset_id,
                ),
            )
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.metadata.scan_id,))
            conn.executemany(
                "INSERT INTO findings (scan_id, finding_key, cve, package_name, priority, payload,"
                " package_type, cvss_score, epss, fixed_version,"
                " update_available, no_fix, kev, exploit) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [_finding_row(result.metadata.scan_id, f) for f in result.findings],
            )

    def list_scans(self, limit: int = 50, *, asset_id: str | None = None) -> list[dict[str, Any]]:
        """스캔 목록. `asset_id` 를 주면 그 자산 것만 (`""` 는 미분류를 뜻한다)."""
        sql = "SELECT scan_id, created_at, metadata, finding_count, policy, asset_id FROM scans"
        params: list[Any] = []
        if asset_id is not None:
            sql += " WHERE asset_id = ?"
            params.append(asset_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "created_at": r["created_at"],
                "finding_count": r["finding_count"],
                "metadata": json.loads(r["metadata"]),
                "policy": json.loads(r["policy"] or "{}"),
                "asset_id": r["asset_id"],
            }
            for r in rows
        ]

    def assign_scan(self, scan_id: str, asset_id: str) -> bool:
        """스캔을 자산에 배정한다. 빈 문자열이면 미분류로 되돌린다."""
        with self._connect() as conn:
            return bool(
                conn.execute(
                    "UPDATE scans SET asset_id = ? WHERE scan_id = ?", (asset_id, scan_id)
                ).rowcount
            )

    def asset_summary(self) -> dict[str, dict[str, Any]]:
        """자산별 마지막 스캔과 누적 스캔 수. 대시보드 한 줄 한 줄이 이것이다.

        자산마다 질의를 돌리면 자산 수만큼 왕복한다. 한 번에 집계한다.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT asset_id, COUNT(*) AS scans, MAX(created_at) AS last_at FROM scans "
                "GROUP BY asset_id"
            ).fetchall()
            latest = conn.execute(
                "SELECT s.asset_id, s.scan_id, s.created_at, s.finding_count, s.metadata FROM scans s "
                "JOIN (SELECT asset_id, MAX(created_at) AS m FROM scans GROUP BY asset_id) t "
                "  ON t.asset_id = s.asset_id AND t.m = s.created_at"
            ).fetchall()

        newest = {r["asset_id"]: r for r in latest}
        summary: dict[str, dict[str, Any]] = {}
        for row in rows:
            last = newest.get(row["asset_id"])
            summary[row["asset_id"]] = {
                "scan_count": row["scans"],
                "last_scan_at": row["last_at"] or "",
                "last_scan_id": last["scan_id"] if last else "",
                "last_finding_count": last["finding_count"] if last else 0,
                "last_sbom_filename": (
                    json.loads(last["metadata"]).get("sbom_filename", "") if last else ""
                ),
            }
        return summary

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
            "asset_id": row["asset_id"],
            "metadata": json.loads(row["metadata"]),
            "enrichment": json.loads(row["enrichment"] or "{}"),
            "policy": json.loads(row["policy"] or "{}"),
            "findings": [json.loads(f["payload"]) for f in findings],
        }

    def get_scan_meta(self, scan_id: str) -> dict[str, Any] | None:
        """스캔이 존재하는가와 그 머리말. **findings 는 읽지 않는다.**

        `get_scan()` 은 48,923건의 payload 를 전부 파싱한다. 존재 여부만
        알면 되는 자리에서 그것을 부르면 요청 하나가 8초가 된다.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT scan_id, created_at, metadata, finding_count, enrichment, policy, asset_id "
                "FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "scan_id": row["scan_id"],
            "created_at": row["created_at"],
            "asset_id": row["asset_id"],
            "finding_count": row["finding_count"],
            "metadata": json.loads(row["metadata"]),
            "enrichment": json.loads(row["enrichment"] or "{}"),
            "policy": json.loads(row["policy"] or "{}"),
        }

    # --- 결과 페이지 -------------------------------------------------------

    @staticmethod
    def _where(
        scan_id: str, priority: str, package_type: str, status: str, query: str
    ) -> tuple[str, list[Any]]:
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if priority:
            clauses.append("priority = ?")
            params.append(priority)
        if package_type:
            clauses.append("package_type = ?")
            params.append(package_type)
        if status in _FILTER_SQL:
            clauses.append(_FILTER_SQL[status])
        if query:
            # LIKE 의 와일드카드가 검색어에 섞이면 엉뚱한 것이 걸린다.
            needle = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(
                "(cve LIKE ? ESCAPE '\\' OR package_name LIKE ? ESCAPE '\\')"
            )
            params += [f"%{needle}%", f"%{needle}%"]
        return " AND ".join(clauses), params

    def page_findings(
        self,
        scan_id: str,
        *,
        sort: str = "priority",
        order: str = "asc",
        priority: str = "",
        package_type: str = "",
        status: str = "",
        query: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """한 페이지분만 돌려준다.

        정렬·필터를 SQL 이 한다. 48,923건짜리 스캔에서 payload 를 전부 파이썬
        객체로 되살려 정렬하면 페이지 한 장에 10초가 걸렸다(실측). 여기서는
        인덱스로 고르고 100건분 payload 만 파싱한다.
        """
        null_last, primary, tie = _SORT_SQL.get(sort) or _SORT_SQL["priority"]
        direction = "DESC" if order == "desc" else "ASC"
        # 미확인을 뒤로 보내는 것은 방향과 무관한 규칙이라 언제나 ASC 다.
        order_by = f"{null_last} ASC, {primary} {direction}, {tie} ASC"

        where, params = self._where(scan_id, priority, package_type, status, query)

        with self._connect() as conn:
            scan_total = conn.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchone()["n"]
            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM findings WHERE {where}", params
            ).fetchone()["n"]
            rows = conn.execute(
                f"SELECT payload FROM findings WHERE {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            types = conn.execute(
                "SELECT DISTINCT package_type FROM findings WHERE scan_id = ? AND package_type != '' "
                "ORDER BY package_type",
                (scan_id,),
            ).fetchall()

        return {
            "findings": [json.loads(r["payload"]) for r in rows],
            "total": total,
            "scan_total": scan_total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < total,
            "package_types": [t["package_type"] for t in types],
        }

    def get_finding(self, scan_id: str, finding_key: str) -> dict[str, Any] | None:
        """항목 하나. 상세 패널을 열 때 그것만 가져온다."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM findings WHERE scan_id = ? AND finding_key = ?",
                (scan_id, finding_key),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def iter_findings(
        self,
        scan_id: str,
        *,
        priority: str = "",
        package_type: str = "",
        status: str = "",
        query: str = "",
        chunk: int = 2000,
    ) -> Iterator[dict[str, Any]]:
        """필터에 맞는 항목을 하나씩 흘려 준다. CSV 내보내기가 쓴다.

        48,923건을 리스트로 만들면 그 자체가 수백 MB 다. 청크로 읽어 흘린다.
        """
        where, params = self._where(scan_id, priority, package_type, status, query)

        # **OFFSET 이 아니라 커서(rowid)로 넘긴다.** OFFSET 은 건너뛸 행을 매번
        # 세므로 뒤로 갈수록 느려진다(48,923건 CSV 에 27초). rowid 커서는 인덱스
        # 탐색 한 번이라 어디를 읽든 같은 값이다.
        #
        # 저장 순서가 곧 우선순위 순이다(save_scan 이 정렬해 넣는다). CSV 는
        # 그 순서면 충분하므로 정렬을 따로 걸지 않는다.
        with self._connect() as conn:
            cursor = 0
            while True:
                rows = conn.execute(
                    f"SELECT rowid, payload FROM findings WHERE {where} AND rowid > ? "
                    f"ORDER BY rowid LIMIT ?",
                    (*params, cursor, chunk),
                ).fetchall()
                if not rows:
                    return
                for row in rows:
                    yield json.loads(row["payload"])
                cursor = rows[-1]["rowid"]

    def finding_keys(
        self,
        scan_id: str,
        *,
        priority: str = "",
        package_type: str = "",
        status: str = "",
        query: str = "",
        limit: int = 10000,
    ) -> tuple[list[str], int]:
        """필터에 맞는 선택 키 전부. "필터 전체 선택" 이 쓴다.

        `(키 목록, 전체 건수)` 를 돌려준다. 상한을 넘으면 목록은 잘리고 건수는
        그대로다 — 화면이 "N건 중 M건만 선택했다"고 말할 수 있어야 한다.
        """
        where, params = self._where(scan_id, priority, package_type, status, query)
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM findings WHERE {where}", params
            ).fetchone()["n"]
            rows = conn.execute(
                f"SELECT finding_key FROM findings WHERE {where} "
                f"ORDER BY priority IS NULL ASC, priority ASC, package_name ASC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [r["finding_key"] for r in rows], total

    def scan_summary(self, scan_id: str) -> dict[str, Any]:
        """요약 타일에 쓰는 집계. 전체를 내려보내지 않고 SQL 로 센다."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT priority, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY priority",
                (scan_id,),
            ).fetchall()
            agg = conn.execute(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT package_name) AS packages, "
                "SUM(update_available) AS updatable, SUM(no_fix) AS nofix, "
                "SUM(kev) AS kev, SUM(exploit) AS exploit "
                "FROM findings WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()

        by_priority = {p: 0 for p in ("P0", "P1", "P2", "P3")}
        for row in rows:
            if row["priority"] in by_priority:
                by_priority[row["priority"]] = row["n"]
        return {
            "total": agg["total"] or 0,
            "by_priority": by_priority,
            "affected_packages": agg["packages"] or 0,
            "update_available": agg["updatable"] or 0,
            "no_fix_available": agg["nofix"] or 0,
            "kev_listed": agg["kev"] or 0,
            "exploit_available": agg["exploit"] or 0,
        }

    def delete_scan(self, scan_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM narratives WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM chains WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM selections WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))

    # --- 선택 -------------------------------------------------------------

    def save_selection(self, scan_id: str, keys: list[str]) -> None:
        """담당자가 고른 항목을 기록한다. 빈 목록은 '전체'를 뜻한다."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO selections (scan_id, keys, created_at) VALUES (?,?,?)",
                (
                    scan_id,
                    json.dumps(list(dict.fromkeys(keys)), ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )

    def get_selection(self, scan_id: str) -> list[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT keys FROM selections WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["keys"]) if row else []

    # --- AI 서술 ----------------------------------------------------------

    def save_narratives(self, scan_id: str, narratives: dict[str, Any], model: str = "") -> None:
        """CVE → 서술 dict 를 덮어쓴다.

        선택한 항목만 생성했다면 그 항목만 갱신된다. 이전에 만들어 둔 다른
        CVE의 서술은 남는다 — 담당자가 몇 번에 나누어 고를 수 있어야 한다.
        """
        if not narratives:
            return
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO narratives (scan_id, cve, payload, model, created_at) "
                "VALUES (?,?,?,?,?)",
                [
                    (scan_id, cve, json.dumps(payload, ensure_ascii=False), model, now)
                    for cve, payload in narratives.items()
                ],
            )

    def get_narratives(self, scan_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT cve, payload FROM narratives WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return {r["cve"]: json.loads(r["payload"]) for r in rows}

    def narrative_meta(self, scan_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(created_at) AS at, MAX(model) AS model "
                "FROM narratives WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return {"count": row["n"] or 0, "generated_at": row["at"] or "", "model": row["model"] or ""}

    def clear_narratives(self, scan_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM narratives WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM chains WHERE scan_id = ?", (scan_id,))

    # --- 연계 분석 --------------------------------------------------------

    def save_chains(self, scan_id: str, chains: dict[str, str], model: str = "") -> None:
        """패키지명 → 연계 분석 서술.

        서술 자체는 공개 데이터에서 나온 산문이지만, **어느 스캔의 어느 패키지에
        붙었는지는 내부 맥락**이라 이 DB 안에만 둔다.
        """
        if not chains:
            return
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO chains (scan_id, package, analysis, model, created_at) "
                "VALUES (?,?,?,?,?)",
                [(scan_id, package, text, model, now) for package, text in chains.items()],
            )

    def get_chains(self, scan_id: str) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT package, analysis FROM chains WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return {r["package"]: r["analysis"] for r in rows}

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
