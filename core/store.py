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
from typing import Any, Iterator, Sequence

from .models import ScanResult, to_jsonable


def _tune(conn: sqlite3.Connection) -> None:
    """SQLite 기본값은 이 크기의 DB에 맞지 않는다.

    48,923건짜리 스캔의 DB는 111MB인데 기본 페이지 캐시는 **2MB**다. 그래서
    같은 쿼리를 두 번 돌려도 매번 디스크를 다시 읽고, 디스크가 느린 환경
    (VM 위의 Windows, 네트워크 드라이브)에서는 그 차이가 화면 지연으로 그대로
    나온다. 실측한 값들이라 근거를 적어 둔다.

    - ``journal_mode=WAL`` — 기본 ``delete`` 는 쓰기마다 저널 파일을 만들고
      지운다. Windows 의 파일 생성/삭제는 비싸고, 읽는 쪽이 쓰는 쪽을 막는다.
      WAL 은 읽기와 쓰기가 서로를 막지 않는다.
    - ``synchronous=NORMAL`` — WAL 에서는 이것으로도 전원이 꺼졌을 때 DB가
      깨지지 않는다(마지막 트랜잭션 몇 개를 잃을 수 있을 뿐이다). 기본
      ``FULL`` 은 커밋마다 fsync 를 부른다.
    - ``cache_size=-65536`` — 64MB. 음수는 페이지 수가 아니라 KiB 다.
    - ``mmap_size`` — 읽기를 메모리 매핑으로 돌려 복사를 한 번 줄인다.
    - ``temp_store=MEMORY`` — ORDER BY 가 임시 B-tree 를 쓸 때 디스크로 나가지
      않게 한다.
    """
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-65536")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA mmap_size=268435456")


def package_key(name: str, installed_version: str) -> str:
    """묶음 하나를 가리키는 키. `이름@설치버전`.

    같은 이름이 서로 다른 버전으로 두 번 깔려 있는 경우가 있고(컨테이너 안팎,
    32/64비트 병존), 그것은 조치도 따로다. 버전을 키에서 빼면 둘이 한 줄로
    합쳐져 "어느 쪽을 올려야 하나"를 알 수 없게 된다.
    """
    return f"{name}@{installed_version}"


def split_package_key(key: str) -> tuple[str, str]:
    """`package_key` 의 역. **마지막 `@` 로 가른다.**

    npm 스코프 패키지는 이름 자체에 `@` 가 있다(`@scope/pkg@1.2.3`). 앞에서
    자르면 이름이 잘린다.
    """
    name, _, version = key.rpartition("@")
    return (name, version) if name else (key, "")


def _sort_columns(payload: dict[str, Any]) -> tuple:
    """정렬·필터에 쓰는 값을 payload 에서 꺼낸다.

    `findings` 테이블의 컬럼 순서와 **정확히** 같아야 한다 —
    package_type · installed_version · cvss_score · epss · fixed_version ·
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
        str(installed.get("version") or ""),
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
#
# 비워 둘 자리에는 `0` 이 아니라 `NEVER` 를 쓴다. `ORDER BY 0` 은 상수가 아니라
# **컬럼 번호**로 읽혀서 `1st ORDER BY term out of range` 로 죽는다 — 실제로
# 패키지·CVE 정렬이 그래서 동작하지 않았다.
NEVER = "0=1"

_SORT_SQL = {
    "priority": ("priority IS NULL", "priority", "package_name"),
    "cvss": ("cvss_score IS NULL", "cvss_score", "cve"),
    "epss": ("epss IS NULL", "epss", "cve"),
    "package": (NEVER, "package_name COLLATE NOCASE", "cve"),
    "cve": (NEVER, "cve", "package_name"),
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
    installed_version TEXT NOT NULL DEFAULT '',
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
-- installed_version 을 쓰는 인덱스는 _migrate 에서 만든다. 이 스크립트는
-- 마이그레이션보다 먼저 돌아서, 컬럼이 아직 없는 기존 DB 에서는 실패한다.

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
            ("installed_version", "TEXT NOT NULL DEFAULT ''"),
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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_pkg "
            "ON findings(scan_id, package_name, installed_version)"
        )
        # 심각도·악용 예측으로 정렬하면 인덱스가 없어 48,923행짜리 임시
        # B-tree 를 매번 만들었다. 정렬 방향이 둘 다 쓰이므로 컬럼만 걸어
        # 두고, "미확인은 뒤로" 규칙은 첫 키(`x IS NULL`)가 처리한다.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(scan_id, cvss_score)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_epss ON findings(scan_id, epss)"
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
                "UPDATE findings SET package_type = ?, installed_version = ?, cvss_score = ?, "
                "epss = ?, fixed_version = ?, update_available = ?, no_fix = ?, kev = ?, "
                "exploit = ? WHERE scan_id = ? AND finding_key = ?",
                updates,
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        _tune(conn)
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
                " package_type, installed_version, cvss_score, epss, fixed_version,"
                " update_available, no_fix, kev, exploit) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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

    # --- 패키지 묶음 -------------------------------------------------------
    #
    # 보고서는 패키지 단위다. 48,923건은 패키지 8,154개가 되는데, 그것도 한
    # 화면에 그릴 양이 아니다. 목록은 SQL 로 집계해 쪽으로 넘기고, 상세는
    # 펼친 묶음만 조립한다.

    def _package_where(
        self, scan_id: str, package_type: str, status: str, query: str,
        scoped: bool = False,
    ) -> tuple[str, list[Any]]:
        """묶음 목록의 WHERE. `_where` 와 달리 등급은 HAVING 에서 본다 —
        묶음의 등급은 그 안에서 가장 급한 것이라 집계 뒤에만 알 수 있다."""
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if package_type:
            clauses.append("package_type = ?")
            params.append(package_type)
        if status in _FILTER_SQL:
            clauses.append(_FILTER_SQL[status])
        if query:
            needle = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(package_name LIKE ? ESCAPE '\\' OR cve LIKE ? ESCAPE '\\')")
            params += [f"%{needle}%", f"%{needle}%"]
        if scoped:
            # 기록해 둔 선택 안으로 좁힌다. 키 목록을 요청마다 실어 보내지
            # 않는다 — 8,154개면 URL 이 수백 KB 다.
            clauses.append(
                "finding_key IN (SELECT value FROM json_each("
                "  (SELECT keys FROM selections WHERE scan_id = ?)))"
            )
            params.append(scan_id)
        return " AND ".join(clauses), params

    #: 묶음 표의 정렬 키. 값은 `(미확인_뒤로, 주키, 동점_처리)`.
    _PKG_SORT = {
        "priority": ("priority IS NULL", "priority", "cve_count DESC"),
        "count": (NEVER, "cve_count", "package_name COLLATE NOCASE"),
        "cvss": ("max_cvss IS NULL", "max_cvss", "package_name COLLATE NOCASE"),
        "epss": ("max_epss IS NULL", "max_epss", "package_name COLLATE NOCASE"),
        "package": (NEVER, "package_name COLLATE NOCASE", "installed_version"),
    }

    PACKAGE_SORT_KEYS = tuple(_PKG_SORT)

    def _package_group_sql(
        self, priority: str
    ) -> tuple[str, str]:
        """집계 SELECT 와 HAVING 을 함께 낸다. 목록·건수·키가 모두 같은 것을 본다."""
        having = "HAVING MIN(priority) = ?" if priority else ""
        group_sql = (
            "SELECT package_name, installed_version, "
            "  MIN(package_type) AS package_type, "
            "  MIN(priority) AS priority, "
            "  COUNT(*) AS cve_count, "
            "  SUM(CASE WHEN fixed_version != '' THEN 1 ELSE 0 END) AS fixable, "
            "  SUM(CASE WHEN fixed_version = '' THEN 1 ELSE 0 END) AS no_fix, "
            "  SUM(kev) AS kev, SUM(exploit) AS exploit, "
            "  MAX(cvss_score) AS max_cvss, MAX(epss) AS max_epss "
            "FROM findings WHERE {where} "
            "GROUP BY package_name, installed_version "
            f"{having}"
        )
        return group_sql, having

    def page_packages(
        self,
        scan_id: str,
        *,
        sort: str = "priority",
        order: str = "asc",
        priority: str = "",
        package_type: str = "",
        status: str = "",
        query: str = "",
        scoped: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """결과 표 한 쪽. **패키지 하나가 한 줄이다.**

        조치는 패키지당 한 번이다 — `openssl` 을 3.0.7로 올리면 CVE 5건이 한
        번에 해소되는데, CVE 단위로 늘어놓으면 같은 패치를 5번 읽게 된다.
        48,923건이 8,154줄이 되고, 그것도 쪽으로 넘긴다.

        수정 버전 목록은 **묶음마다 따로 묻지 않는다.** 25개를 그리려고 쿼리를
        26번 하던 것을 `GROUP_CONCAT` 한 번으로 바꿨다.
        """
        where, params = self._package_where(scan_id, package_type, status, query, scoped)
        group_sql, having = self._package_group_sql(priority)
        group_sql = group_sql.format(where=where)
        having_params = [priority] if priority else []

        null_last, primary, tie = self._PKG_SORT.get(sort) or self._PKG_SORT["priority"]
        direction = "DESC" if order == "desc" else "ASC"
        order_by = f"{null_last} ASC, {primary} {direction}, {tie}"

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM ({group_sql})", (*params, *having_params)
            ).fetchone()["n"]
            rows = conn.execute(
                f"SELECT g.*, ("
                "  SELECT GROUP_CONCAT(DISTINCT f.fixed_version) FROM findings f "
                "  WHERE f.scan_id = ? AND f.package_name = g.package_name "
                "    AND f.installed_version = g.installed_version AND f.fixed_version != ''"
                f") AS fixed_versions FROM ({group_sql}) g "
                f"ORDER BY {order_by} LIMIT ? OFFSET ?",
                (scan_id, *params, *having_params, limit, offset),
            ).fetchall()

        groups = [{
            "package": r["package_name"],
            "package_type": r["package_type"] or "",
            "installed_version": r["installed_version"],
            "priority": r["priority"],
            "cve_count": r["cve_count"],
            "fixable_count": r["fixable"],
            "no_fix_count": r["no_fix"],
            "kev_count": r["kev"] or 0,
            "exploit_count": r["exploit"] or 0,
            "max_cvss": r["max_cvss"],
            "max_epss": r["max_epss"],
            "fixed_versions": (r["fixed_versions"] or "").split(",") if r["fixed_versions"] else [],
        } for r in rows]

        return {
            "packages": groups,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(groups) < total,
        }

    def package_keys(
        self,
        scan_id: str,
        *,
        priority: str = "",
        package_type: str = "",
        status: str = "",
        query: str = "",
        scoped: bool = False,
    ) -> list[str]:
        """지금 조건에 맞는 묶음 키 전부. "전체 선택" 이 쓴다.

        상한을 두지 않는다. 키는 `이름@버전` 짧은 문자열이고, 8,154개라도
        수백 KB다 — 담당자가 "전체"라고 했으면 전체여야 한다.
        """
        where, params = self._package_where(scan_id, package_type, status, query, scoped)
        group_sql, _ = self._package_group_sql(priority)
        group_sql = group_sql.format(where=where)
        having_params = [priority] if priority else []
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT package_name, installed_version FROM ({group_sql}) "
                "ORDER BY priority IS NULL ASC, priority ASC, package_name ASC",
                (*params, *having_params),
            ).fetchall()
        return [package_key(r["package_name"], r["installed_version"]) for r in rows]

    def existing_finding_keys(self, scan_id: str, keys: Sequence[str]) -> list[str]:
        """주어진 키 중 이 스캔에 실제로 있는 것만. 없는 것은 조용히 버린다.

        스캔을 바꾼 뒤 옛 선택이 남아 있으면 그 키들은 이 스캔에 없다. 그것을
        오류로 내면 화면이 멈추고, 그대로 저장하면 보고서 범위가 거짓이 된다.
        """
        wanted = [k for k in keys if k]
        if not wanted:
            return []
        with self._connect() as conn:
            return [r["finding_key"] for r in conn.execute(
                "SELECT finding_key FROM findings WHERE scan_id = ? "
                "AND finding_key IN (SELECT value FROM json_each(?))",
                (scan_id, json.dumps(wanted)),
            )]

    def packages_for_finding_keys(self, scan_id: str, keys: Sequence[str]) -> list[str]:
        """finding 키들이 속한 묶음 키. 저장된 선택을 화면 체크로 되돌린다."""
        wanted = [k for k in keys if k]
        if not wanted:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT package_name, installed_version FROM findings "
                "WHERE scan_id = ? AND finding_key IN (SELECT value FROM json_each(?))",
                (scan_id, json.dumps(wanted)),
            ).fetchall()
        return [package_key(r["package_name"], r["installed_version"]) for r in rows]

    def findings_by_keys(self, scan_id: str, keys: Sequence[str]) -> list[dict[str, Any]]:
        """주어진 키의 payload 만. **스캔 전체를 되살리지 않는다.**

        이그레스 미리보기가 48,923건을 파이썬 객체로 만들면 그 한 번이 9초다.
        보여 줄 만큼만 읽는다.
        """
        wanted = [k for k in keys if k]
        if not wanted:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM findings WHERE scan_id = ? "
                "AND finding_key IN (SELECT value FROM json_each(?)) "
                "ORDER BY priority IS NULL ASC, priority ASC, cve ASC",
                (scan_id, json.dumps(wanted)),
            ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def selected_packages(self, scan_id: str) -> list[str]:
        """기록된 선택이 덮는 묶음 키. **finding 키를 거치지 않는다.**

        화면이 되살려야 하는 것은 체크된 패키지 목록이다. 48,923개 finding
        키를 받아 파이썬에서 되돌리면 그 한 번이 2.4초에 4MB 다.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT package_name, installed_version FROM findings "
                "WHERE scan_id = ? AND finding_key IN ("
                "  SELECT value FROM json_each("
                "    (SELECT keys FROM selections WHERE scan_id = ?)))",
                (scan_id, scan_id),
            ).fetchall()
        return [package_key(r["package_name"], r["installed_version"]) for r in rows]

    # --- 두 스캔의 변화 ----------------------------------------------------
    #
    # 비교 축은 `(cve, 설치 패키지명)` 이다. `finding_key` 는 설치 버전을
    # 포함하므로 패치하면 키가 바뀐다 — 그것으로 비교하면 "패치했더니 하나
    # 사라지고 하나 생겼다" 가 되어 실제로 무엇이 달라졌는지 알 수 없다.
    #
    # **SQL 로 한다.** 예전에는 두 스캔의 payload 를 전부 파이썬 객체로 되살려
    # 사전 두 개를 만들었다. 48,923건짜리 스캔 둘이면 그 한 번이 20초가 넘고,
    # 결과 수만 줄을 화면으로 그대로 내려보내 스크롤도 되지 않았다.

    _DIFF_SQL = {
        # 신규: head 에 있고 base 에 없는 것.
        "added": (
            "FROM findings h WHERE h.scan_id = :head AND NOT EXISTS ("
            "  SELECT 1 FROM findings b WHERE b.scan_id = :base "
            "    AND b.cve = h.cve AND b.package_name = h.package_name)"
        ),
        # 해소: base 에 있었는데 head 에 없는 것.
        "resolved": (
            "FROM findings h WHERE h.scan_id = :base AND NOT EXISTS ("
            "  SELECT 1 FROM findings b WHERE b.scan_id = :head "
            "    AND b.cve = h.cve AND b.package_name = h.package_name)"
        ),
        # 유지: 양쪽에 다 있는 것. 이전 설치 버전을 함께 낸다 — 버전이 올랐는데도
        # 여전히 취약한 경우(부분 패치)는 신규도 해소도 아니지만 봐야 한다.
        "remaining": (
            "FROM findings h WHERE h.scan_id = :head AND EXISTS ("
            "  SELECT 1 FROM findings b WHERE b.scan_id = :base "
            "    AND b.cve = h.cve AND b.package_name = h.package_name)"
        ),
    }

    DIFF_KINDS = tuple(_DIFF_SQL)

    def diff_counts(self, base: str, head: str) -> dict[str, int]:
        """세 갈래의 건수만. 화면 머리말은 이것만 있으면 그려진다."""
        params = {"base": base, "head": head}
        with self._connect() as conn:
            return {
                kind: conn.execute(f"SELECT COUNT(*) AS n {sql}", params).fetchone()["n"]
                for kind, sql in self._DIFF_SQL.items()
            }

    def diff_page(
        self, base: str, head: str, kind: str, *, offset: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        """한 갈래의 한 쪽. 수만 줄을 한 번에 그리지 않는다."""
        sql = self._DIFF_SQL.get(kind)
        if sql is None:
            raise ValueError(f"알 수 없는 갈래: {kind}")
        params = {"base": base, "head": head, "limit": limit, "offset": offset}

        previous = (
            "(SELECT b.installed_version FROM findings b WHERE b.scan_id = :base "
            "   AND b.cve = h.cve AND b.package_name = h.package_name LIMIT 1)"
            if kind == "remaining" else "''"
        )
        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS n {sql}", params).fetchone()["n"]
            rows = conn.execute(
                f"SELECT h.cve, h.package_name, h.installed_version, h.fixed_version, "
                f"       h.priority, {previous} AS previous_version {sql} "
                "ORDER BY h.package_name COLLATE NOCASE, h.cve LIMIT :limit OFFSET :offset",
                params,
            ).fetchall()

        return {
            "kind": kind,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < total,
            "changes": [{
                "cve": r["cve"],
                "package_name": r["package_name"],
                "installed_version": r["installed_version"],
                "previous_version": r["previous_version"] or "",
                "fixed_version": r["fixed_version"],
                "priority": r["priority"],
            } for r in rows],
        }

    def package_types(self, scan_id: str) -> list[str]:
        """이 스캔에 실제로 있는 패키지 유형. 필터 선택지를 만든다."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT package_type FROM findings "
                "WHERE scan_id = ? AND package_type != '' ORDER BY package_type",
                (scan_id,),
            ).fetchall()
        return [r["package_type"] for r in rows]

    def finding_keys_for_packages(self, scan_id: str, packages: Sequence[str]) -> list[str]:
        """묶음 키 목록을 그 안의 finding 키 전부로 편다.

        화면은 패키지를 고르지만 보고서·이그레스는 finding 단위로 돈다. 그
        변환을 **쿼리 한 번**으로 한다 — 400개씩 끊어 21번 묻던 것이 8,154개에
        10초였다. `이름 || '@' || 버전` 이 곧 묶음 키이므로 그대로 대조한다.
        """
        wanted = [k for k in packages if k]
        if not wanted:
            return []
        with self._connect() as conn:
            return [r["finding_key"] for r in conn.execute(
                "SELECT finding_key FROM findings WHERE scan_id = ? "
                "AND (package_name || '@' || installed_version) "
                "    IN (SELECT value FROM json_each(?))",
                (scan_id, json.dumps(wanted)),
            )]

    def package_findings(
        self, scan_id: str, package: str, installed_version: str = ""
    ) -> list[dict[str, Any]]:
        """묶음 하나에 속한 항목 전부. 펼쳤을 때만 부른다."""
        sql = ("SELECT payload FROM findings WHERE scan_id = ? AND package_name = ?")
        params: list[Any] = [scan_id, package]
        if installed_version:
            sql += " AND installed_version = ?"
            params.append(installed_version)
        sql += " ORDER BY priority IS NULL ASC, priority ASC, cve ASC"
        with self._connect() as conn:
            return [json.loads(r["payload"]) for r in conn.execute(sql, params)]

    def package_totals(self, scan_id: str) -> dict[str, int]:
        """조치 대상 요약 — 몇 개를 올리면 몇 건이 해소되는가."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS packages, "
                "  SUM(CASE WHEN fixable > 0 THEN 1 ELSE 0 END) AS fixable_packages, "
                "  SUM(fixable) AS fixable, SUM(no_fix) AS no_fix "
                "FROM (SELECT SUM(CASE WHEN fixed_version != '' THEN 1 ELSE 0 END) AS fixable, "
                "             SUM(CASE WHEN fixed_version = '' THEN 1 ELSE 0 END) AS no_fix "
                "      FROM findings WHERE scan_id = ? "
                "      GROUP BY package_name, installed_version)",
                (scan_id,),
            ).fetchone()
        return {
            "packages": row["packages"] or 0,
            "fixable_packages": row["fixable_packages"] or 0,
            "fixable": row["fixable"] or 0,
            "no_fix": row["no_fix"] or 0,
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
