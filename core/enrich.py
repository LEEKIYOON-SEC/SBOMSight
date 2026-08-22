"""위협정보 보강 — EPSS · CISA KEV · 공개 Exploit · NVD.

**KEV와 Exploit은 다른 개념이다.** 이 모듈은 둘을 절대 합치지 않는다:

    kev                = CISA가 실제 악용을 확인해 카탈로그에 등재했는가
    exploit_available  = 공개된 exploit / PoC 코드가 존재하는가

KEV에 있는데 공개 exploit이 없을 수 있고, 공개 PoC가 있는데 KEV에는 없을
수도 있다. 그래서 별개 필드로 두고, Rule Engine에서도 독립 조건으로 평가한다.

모든 exploit 판정에는 `exploit_sources`로 출처가 따라붙는다. 출처를 댈 수
없는 exploit 주장은 리포트에 쓰지 않는다. 확인하지 못했으면 `false`가 아니라
`unknown`이다 — "없다"와 "모른다"는 다른 이야기다.

수집물은 파일 캐시에 스냅샷 기준일과 함께 남는다. 오프라인에서도 마지막
스냅샷으로 동작하며, 낡았으면 리포트에 `stale_snapshot`으로 표기된다.
"""

from __future__ import annotations

import csv
import dataclasses
import gzip
import io
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import Config, get_config
from .models import ExploitMaturity, ExploitSource, Finding, Ternary, VulnIntel
from .store import Store

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 수집 결과 보고
# ---------------------------------------------------------------------------


@dataclass
class SourceStatus:
    """소스 하나의 수집 결과. UI의 '위협정보 보강' 단계에 그대로 표시된다."""

    name: str
    state: str = "skipped"    # ok / cached / failed / skipped / offline / disabled
    snapshot_date: str = ""
    fetched_at: str = ""
    entries: int = 0
    matched: int = 0
    detail: str = ""

    @property
    def usable(self) -> bool:
        return self.state in ("ok", "cached", "offline") and self.entries > 0


@dataclass
class EnrichmentReport:
    sources: dict[str, SourceStatus] = field(default_factory=dict)

    def add(self, status: SourceStatus) -> None:
        self.sources[status.name] = status

    def to_dict(self) -> dict[str, Any]:
        return {name: dataclasses.asdict(s) for name, s in self.sources.items()}


# ---------------------------------------------------------------------------
# 대량 소스 공통 — 파일 캐시 + TTL + 오프라인 폴백
# ---------------------------------------------------------------------------


class BulkSource:
    """CVE 전체를 한 파일로 받아 인덱스를 만드는 소스."""

    name = ""
    url = ""
    # 선택 소스는 명시적으로 켜야 수집한다. 라이선스 검토가 필요하거나,
    # 켜서 얻는 신호가 판정에 결정적이지 않은 것들이다.
    optional = False
    license = ""

    def __init__(self, config: Config):
        self.config = config

    # 하위 클래스가 구현한다.
    def parse(self, raw: bytes) -> tuple[dict[str, Any], str]:
        raise NotImplementedError

    # -- 캐시 -------------------------------------------------------------

    @property
    def cache_path(self) -> Path:
        return self.config.cache_dir / f"{self.name}.json"

    def _read_cache(self) -> tuple[dict[str, Any], str, str] | None:
        if not self.cache_path.is_file():
            return None
        try:
            blob = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return blob.get("index") or {}, str(blob.get("snapshot_date") or ""), str(blob.get("fetched_at") or "")

    def _write_cache(self, index: dict[str, Any], snapshot_date: str) -> str:
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps(
                {"snapshot_date": snapshot_date, "fetched_at": fetched_at, "index": index},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return fetched_at

    def _cache_is_fresh(self, fetched_at: str) -> bool:
        if not fetched_at:
            return False
        try:
            stamp = datetime.fromisoformat(fetched_at)
        except ValueError:
            return False
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - stamp < timedelta(hours=self.config.enrich_ttl_hours)

    # -- 적재 -------------------------------------------------------------

    def enabled(self) -> bool:
        """선택 소스인지, 켜져 있는지."""
        return not self.optional or self.name in self.config.optional_sources

    def load(self, *, force: bool = False) -> tuple[dict[str, Any], SourceStatus]:
        status = SourceStatus(name=self.name)

        if not self.enabled():
            # **끈 것을 '없음'으로 처리하지 않는다.** 이 소스가 담당하던 신호는
            # unknown 으로 남고, Rule Engine 이 그렇게 표시한다.
            status.state = "disabled"
            status.detail = (
                f"기본 꺼짐 — SBOMSIGHT_COLLECT_{self.name.upper()}=1 로 켤 수 있습니다."
                + (f" 라이선스: {self.license}" if self.license else "")
            )
            return {}, status

        cached = self._read_cache()

        if cached and not force:
            index, snapshot_date, fetched_at = cached
            if self.config.offline:
                status.state = "offline"
                status.detail = "오프라인 모드 — 마지막 스냅샷을 사용했다"
                status.snapshot_date, status.fetched_at, status.entries = snapshot_date, fetched_at, len(index)
                return index, status
            if self._cache_is_fresh(fetched_at):
                status.state = "cached"
                status.snapshot_date, status.fetched_at, status.entries = snapshot_date, fetched_at, len(index)
                return index, status

        if self.config.offline:
            status.state = "offline"
            status.detail = "오프라인 모드이고 캐시도 없다 — 이 소스는 unknown으로 남는다"
            return {}, status

        try:
            import requests

            response = requests.get(self.url, timeout=120)
            response.raise_for_status()
            index, snapshot_date = self.parse(response.content)
        except Exception as exc:  # noqa: BLE001 - 어떤 실패든 캐시로 물러선다
            if cached:
                index, snapshot_date, fetched_at = cached
                status.state = "cached"
                status.detail = f"수집 실패, 캐시 사용: {type(exc).__name__}: {exc}"
                status.snapshot_date, status.fetched_at, status.entries = snapshot_date, fetched_at, len(index)
                return index, status
            status.state = "failed"
            status.detail = f"{type(exc).__name__}: {exc}"
            return {}, status

        status.fetched_at = self._write_cache(index, snapshot_date)
        status.state = "ok"
        status.snapshot_date = snapshot_date
        status.entries = len(index)
        return index, status


class EpssSource(BulkSource):
    """FIRST EPSS 일일 스냅샷 (CSV.gz)."""

    name = "epss"

    def __init__(self, config: Config):
        super().__init__(config)
        self.url = config.epss_csv_url

    def parse(self, raw: bytes) -> tuple[dict[str, Any], str]:
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8", errors="replace")

        # 첫 줄 주석에 스냅샷 기준일이 있다:
        #   #model_version:v2025.03.14,score_date:2026-08-18T00:00:00+0000
        snapshot_date = ""
        lines = text.splitlines()
        if lines and lines[0].startswith("#"):
            m = re.search(r"score_date:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", lines[0])
            if m:
                snapshot_date = m.group(1)
            lines = lines[1:]

        index: dict[str, Any] = {}
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                index[cve] = float(row.get("epss") or 0)
            except ValueError:
                continue
        return index, snapshot_date


class KevSource(BulkSource):
    """CISA Known Exploited Vulnerabilities 카탈로그.

    등재 = **실제 악용이 확인됨**. 공개 exploit 코드의 존재 여부와는 다르다.
    """

    name = "kev"

    def __init__(self, config: Config):
        super().__init__(config)
        self.url = config.kev_json_url

    def parse(self, raw: bytes) -> tuple[dict[str, Any], str]:
        payload = json.loads(raw.decode("utf-8"))
        snapshot_date = str(payload.get("dateReleased") or "")[:10]
        index: dict[str, Any] = {}
        for entry in payload.get("vulnerabilities") or ():
            cve = str(entry.get("cveID") or "").strip().upper()
            if not cve:
                continue
            index[cve] = {
                "date_added": str(entry.get("dateAdded") or ""),
                "ransomware": str(entry.get("knownRansomwareCampaignUse") or "Unknown"),
                "vendor": str(entry.get("vendorProject") or ""),
                "product": str(entry.get("product") or ""),
                "required_action": str(entry.get("requiredAction") or ""),
                "due_date": str(entry.get("dueDate") or ""),
            }
        return index, snapshot_date


class ExploitDbSource(BulkSource):
    """Exploit-DB 인덱스. 공개 exploit/PoC 코드의 존재를 알려 준다.

    **기본은 꺼져 있다** (`SBOMSIGHT_COLLECT_EXPLOITDB=1` 로 켠다). 두 가지 이유다.

    1. Exploit-DB 는 GPL-2.0 (copyleft) 로 배포된다. 조회에만 쓰는 것과 우리
       산출물에 담아 배포하는 것은 성격이 다르고, 사내 반입·배포 기준에 맞는지는
       확인이 필요하다. (저는 법률 판단을 할 수 없습니다. 기본을 끔으로 두는
       이유가 이것입니다.)
    2. 켜서 얻는 것은 "공격코드가 공개되어 있다"는 신호 하나인데, 실제 악용
       확인(KEV)과 악용 확률(EPSS)은 Grype 가 이미 준다. 우선순위 판정에
       결정적이지 않다.
    """

    name = "exploitdb"
    license = "GPL-2.0 (copyleft — 사내 반입·배포 기준 확인 필요)"
    optional = True
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    def parse(self, raw: bytes) -> tuple[dict[str, Any], str]:
        text = raw.decode("utf-8", errors="replace")
        index: dict[str, list[dict[str, str]]] = {}
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            codes = row.get("codes") or ""
            if "CVE-" not in codes.upper():
                continue
            edb_id = (row.get("id") or "").strip()
            verified = (row.get("verified") or "").strip() == "1"
            for cve in {m.upper() for m in _CVE_RE.findall(codes)}:
                index.setdefault(cve, []).append(
                    {
                        "ref": f"EDB-{edb_id}",
                        "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                        "title": (row.get("description") or "").strip()[:160],
                        "verified": "1" if verified else "0",
                    }
                )
        return index, datetime.now(timezone.utc).date().isoformat()


class MetasploitSource(BulkSource):
    """Metasploit 모듈 인덱스.

    모듈이 존재한다는 것은 **즉시 사용 가능한 공격 도구가 공개되어 있다**는
    뜻이므로 exploit_maturity를 weaponized로 본다. PoC 코드 한 조각이 있는
    것과는 다른 수준의 신호다.

    기본은 꺼져 있다 (`SBOMSIGHT_COLLECT_METASPLOIT=1` 로 켠다). 라이선스는
    BSD 3-Clause 계열이라 고지하면 무난하지만, 이 신호 없이도 KEV·EPSS 로
    우선순위가 정해지므로 네트워크를 쓰지 않는 쪽을 기본으로 둔다.
    """

    name = "metasploit"
    license = "BSD 3-Clause 계열 (출처 고지 권장)"
    optional = True
    url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

    def parse(self, raw: bytes) -> tuple[dict[str, Any], str]:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        index: dict[str, list[dict[str, str]]] = {}
        for path, module in (payload or {}).items():
            if not isinstance(module, dict):
                continue
            for ref in module.get("references") or ():
                text = str(ref)
                for cve in {m.upper() for m in _CVE_RE.findall(text)}:
                    index.setdefault(cve, []).append(
                        {
                            "ref": str(module.get("fullname") or path),
                            "url": "https://github.com/rapid7/metasploit-framework",
                            "title": str(module.get("name") or "")[:160],
                        }
                    )
        return index, datetime.now(timezone.utc).date().isoformat()


# ---------------------------------------------------------------------------
# NVD — CWE 보강 (건별, 레이트리밋)
# ---------------------------------------------------------------------------


class NvdSource:
    """CVE별 CWE를 채운다. Grype 출력에는 CWE가 없다.

    NVD API는 레이트리밋이 빡빡하다(키 없으면 30초당 5건). 그래서 SQLite에
    영구 캐시하고, 한 번의 스캔에서 조회할 건수에 예산을 둔다. 예산을 넘긴
    CVE는 CWE 없이 남고 리포트에 그렇게 표기된다.
    """

    name = "nvd"
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Config, store: Store):
        self.config = config
        self.store = store

    def lookup(self, cves: list[str], *, budget: int) -> tuple[dict[str, Any], SourceStatus]:
        status = SourceStatus(name=self.name)
        result: dict[str, Any] = {}

        cached = self.store.cache_get_many("nvd", cves)
        for cve, (payload, _fetched) in cached.items():
            result[cve] = payload
        missing = [c for c in cves if c not in result]

        if not missing:
            status.state = "cached"
            status.entries = len(result)
            return result, status

        if self.config.offline:
            status.state = "offline"
            status.entries = len(result)
            status.detail = f"오프라인 — {len(missing)}건은 CWE 없이 남는다"
            return result, status

        delay = 0.7 if self.config.nvd_api_key else 6.5   # 레이트리밋 준수
        headers = {"apiKey": self.config.nvd_api_key} if self.config.nvd_api_key else {}
        fetched: dict[str, Any] = {}
        errors = 0

        try:
            import requests
        except ImportError:
            status.state = "failed"
            status.detail = "requests 미설치"
            return result, status

        for cve in missing[:budget]:
            try:
                response = requests.get(
                    self.endpoint, params={"cveId": cve}, headers=headers, timeout=30
                )
                response.raise_for_status()
                fetched[cve] = self._extract(response.json())
            except Exception:  # noqa: BLE001 - 개별 실패는 그 CVE만 포기한다
                errors += 1
                if errors >= 3:
                    status.detail = "연속 실패로 NVD 조회를 중단했다"
                    break
            time.sleep(delay)

        if fetched:
            self.store.cache_put_many("nvd", fetched)
            result.update(fetched)

        skipped = len(missing) - len(fetched)
        status.state = "ok" if fetched else ("failed" if errors else "skipped")
        status.entries = len(result)
        if skipped > 0:
            status.detail = (status.detail + "; " if status.detail else "") + \
                f"{skipped}건은 예산/실패로 CWE 미확보"
        return result, status

    @staticmethod
    def _extract(payload: dict[str, Any]) -> dict[str, Any]:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return {"cwe": [], "published": ""}
        cve = vulns[0].get("cve") or {}
        cwes: list[str] = []
        for weakness in cve.get("weaknesses") or ():
            for desc in weakness.get("description") or ():
                value = str(desc.get("value") or "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        return {
            "cwe": sorted(set(cwes)),
            "published": str(cve.get("published") or "")[:10],
        }


# ---------------------------------------------------------------------------
# 보강기
# ---------------------------------------------------------------------------


def _maturity(exploitdb_hits: list[dict], metasploit_hits: list[dict]) -> ExploitMaturity:
    if metasploit_hits:
        return ExploitMaturity.WEAPONIZED
    if exploitdb_hits:
        return ExploitMaturity.PUBLIC_POC
    return ExploitMaturity.NONE


class Enricher:
    def __init__(self, config: Config | None = None, store: Store | None = None):
        self.config = config or get_config()
        self.config.ensure_dirs()
        self.store = store or Store(self.config.db_path)

    def enrich(
        self,
        findings: Iterable[Finding],
        *,
        force: bool = False,
        nvd_budget: int = 40,
    ) -> tuple[tuple[Finding, ...], EnrichmentReport]:
        findings = tuple(findings)
        report = EnrichmentReport()
        cves = sorted({f.intel.cve.upper() for f in findings if f.intel.cve})

        epss_index, epss_status = EpssSource(self.config).load(force=force)
        kev_index, kev_status = KevSource(self.config).load(force=force)
        edb_index, edb_status = ExploitDbSource(self.config).load(force=force)
        msf_index, msf_status = MetasploitSource(self.config).load(force=force)
        nvd_index, nvd_status = NvdSource(self.config, self.store).lookup(cves, budget=nvd_budget)

        for status, index in (
            (epss_status, epss_index),
            (kev_status, kev_index),
            (edb_status, edb_index),
            (msf_status, msf_index),
        ):
            status.matched = sum(1 for c in cves if c in index)
            report.add(status)
        nvd_status.matched = sum(1 for c in cves if c in nvd_index)
        report.add(nvd_status)

        enriched = tuple(
            self._apply_to(
                finding,
                epss_index=epss_index, epss_status=epss_status,
                kev_index=kev_index, kev_status=kev_status,
                edb_index=edb_index, edb_status=edb_status,
                msf_index=msf_index, msf_status=msf_status,
                nvd_index=nvd_index,
            )
            for finding in findings
        )
        return enriched, report

    def _apply_to(
        self,
        finding: Finding,
        *,
        epss_index: dict, epss_status: SourceStatus,
        kev_index: dict, kev_status: SourceStatus,
        edb_index: dict, edb_status: SourceStatus,
        msf_index: dict, msf_status: SourceStatus,
        nvd_index: dict,
    ) -> Finding:
        cve = finding.intel.cve.upper()
        patch: dict[str, Any] = {}

        # --- EPSS ---------------------------------------------------------
        # **Grype 가 준 값이 있으면 건드리지 않는다.** 판정의 근간(CVSS·수정 상태)과
        # 같은 출처에서 온 값이라, 다른 날짜의 외부 스냅샷으로 덮어쓰면 한 화면
        # 안에서 두 시점이 섞인다. 비어 있을 때만 채운다.
        if finding.intel.epss is None and epss_status.usable:
            row = epss_index.get(cve)
            if row is not None:
                patch["epss"] = row
            patch["epss_snapshot_date"] = epss_status.snapshot_date
        # 소스를 못 쓴 경우 epss는 None으로 남고, Rule Engine이
        # unknown_epss 플래그를 세운다. 0.0으로 채우지 않는다.

        # --- CISA KEV -----------------------------------------------------
        # 여기도 Grype 가 답했으면 그 답을 쓴다.
        if finding.intel.kev is Ternary.UNKNOWN and kev_status.usable:
            entry = kev_index.get(cve)
            patch["kev"] = Ternary.TRUE if entry else Ternary.FALSE
            patch["kev_snapshot_date"] = kev_status.snapshot_date
            if entry:
                patch["kev_date_added"] = entry.get("date_added", "")
                patch["kev_ransomware_use"] = entry.get("ransomware", "Unknown")
        # 조회 실패 시 kev는 UNKNOWN으로 남는다 — "등재 안 됨"이 아니다.

        # --- 공개 Exploit (KEV와 독립) ---------------------------------------
        sources: list[ExploitSource] = []
        edb_hits = edb_index.get(cve, []) if edb_status.usable else []
        msf_hits = msf_index.get(cve, []) if msf_status.usable else []
        for hit in edb_hits:
            sources.append(
                ExploitSource(
                    source="exploit_db",
                    ref=hit.get("ref", ""),
                    note=("검증됨" if hit.get("verified") == "1" else "") or hit.get("title", ""),
                )
            )
        for hit in msf_hits:
            sources.append(
                ExploitSource(source="metasploit", ref=hit.get("ref", ""), note=hit.get("title", ""))
            )

        if edb_status.usable or msf_status.usable:
            patch["exploit_available"] = Ternary.TRUE if sources else Ternary.FALSE
            patch["exploit_maturity"] = _maturity(edb_hits, msf_hits)
            patch["exploit_sources"] = tuple(sources)
        # 어느 소스도 못 쓴 경우 exploit_available은 UNKNOWN으로 남는다.
        # "공개 exploit이 없다"고 단정하지 않는다.

        # --- NVD (CWE) -----------------------------------------------------
        nvd = nvd_index.get(cve)
        if nvd:
            if nvd.get("cwe"):
                patch["cwe"] = tuple(nvd["cwe"])
            if nvd.get("published") and not finding.intel.published:
                patch["published"] = nvd["published"]

        if not patch:
            return finding
        return Finding(
            installed=finding.installed,
            advisory=finding.advisory,
            intel=dataclasses.replace(finding.intel, **patch),
            detection=finding.detection,
            fix=finding.fix,
            verdict=finding.verdict,
        )
