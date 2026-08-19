"""위협정보 보강 테스트.

가장 중요한 계약: **확인하지 못한 것을 '없다'고 하지 않는다.** 소스를 못
읽었으면 unknown으로 남아야 하고, 그래야 Rule Engine이 unknown_* 플래그를
세워 리포트에 "확인하지 못했다"고 적을 수 있다.
"""

import gzip
import json

import pytest

from core.config import Config
from core.enrich import (
    Enricher,
    EpssSource,
    ExploitDbSource,
    KevSource,
    MetasploitSource,
)
from core.models import (
    AdvisoryPackage,
    ExploitMaturity,
    Finding,
    InstalledPackage,
    Ternary,
    VulnIntel,
)
from core.store import Store

EPSS_CSV = (
    b"#model_version:v2025.03.14,score_date:2026-08-18T00:00:00+0000\n"
    b"cve,epss,percentile\n"
    b"CVE-2024-3094,0.913400,0.999100\n"
    b"CVE-2024-2511,0.004300,0.512000\n"
)

KEV_JSON = json.dumps(
    {
        "catalogVersion": "2026.08.18",
        "dateReleased": "2026-08-18T12:00:00.0000Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-3094",
                "dateAdded": "2024-03-29",
                "knownRansomwareCampaignUse": "Unknown",
                "vendorProject": "XZ",
                "product": "xz",
            }
        ],
    }
).encode()

EDB_CSV = (
    b"id,file,description,date_published,author,type,platform,port,date_added,"
    b"date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    b'52128,exploits/linux/x.py,"xz backdoor rce",2024-04-01,someone,remote,linux,,'
    b"2024-04-01,,1,CVE-2024-3094;OSVDB-1,,,,,\n"
    b'52129,exploits/multi/y.rb,"cross-spawn redos",2024-11-01,other,dos,multi,,'
    b"2024-11-01,,0,CVE-2024-21538,,,,,\n"
)

MSF_JSON = json.dumps(
    {
        "exploit/linux/local/xz_backdoor": {
            "fullname": "exploit/linux/local/xz_backdoor",
            "name": "XZ Utils Backdoor RCE",
            "references": ["CVE-2024-3094", "URL-https://example.test"],
        }
    }
).encode()


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path / "data"
    cfg.ensure_dirs()
    cfg.offline = True          # 테스트는 네트워크를 타지 않는다
    return cfg


def seed_caches(config, *, epss=True, kev=True, edb=True, msf=True):
    """오프라인 폴백 경로를 쓰기 위해 캐시 파일을 미리 깔아 둔다."""
    pairs = [
        (EpssSource(config), gzip.compress(EPSS_CSV), epss),
        (KevSource(config), KEV_JSON, kev),
        (ExploitDbSource(config), EDB_CSV, edb),
        (MetasploitSource(config), MSF_JSON, msf),
    ]
    for source, raw, enabled in pairs:
        if not enabled:
            continue
        index, snapshot = source.parse(raw)
        source._write_cache(index, snapshot)


def make_finding(cve):
    pkg = InstalledPackage(name="pkg", version="1.0.0", type="npm")
    adv = AdvisoryPackage(advisory_package="pkg", advisory_ecosystem="npm", fixed_version="2.0.0")
    return Finding(installed=pkg, advisory=adv, intel=VulnIntel(cve=cve))


class TestParsers:
    def test_epss_reads_snapshot_date_from_header(self, config):
        index, snapshot = EpssSource(config).parse(gzip.compress(EPSS_CSV))
        assert snapshot == "2026-08-18"
        assert index["CVE-2024-3094"] == [0.9134, 0.9991]

    def test_epss_handles_uncompressed_csv(self, config):
        index, _ = EpssSource(config).parse(EPSS_CSV)
        assert "CVE-2024-3094" in index

    def test_kev_reads_release_date_and_ransomware_flag(self, config):
        index, snapshot = KevSource(config).parse(KEV_JSON)
        assert snapshot == "2026-08-18"
        assert index["CVE-2024-3094"]["date_added"] == "2024-03-29"
        assert index["CVE-2024-3094"]["ransomware"] == "Unknown"

    def test_exploitdb_indexes_by_cve_and_keeps_ref(self, config):
        index, _ = ExploitDbSource(config).parse(EDB_CSV)
        assert index["CVE-2024-3094"][0]["ref"] == "EDB-52128"
        assert index["CVE-2024-21538"][0]["verified"] == "0"

    def test_metasploit_indexes_module_fullname(self, config):
        index, _ = MetasploitSource(config).parse(MSF_JSON)
        assert index["CVE-2024-3094"][0]["ref"] == "exploit/linux/local/xz_backdoor"


class TestEnrichment:
    def test_full_enrichment_populates_public_intel(self, config, tmp_path):
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), report = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)

        intel = finding.intel
        assert intel.epss == 0.9134
        assert intel.epss_percentile == 0.9991
        assert intel.epss_snapshot_date == "2026-08-18"
        assert intel.kev is Ternary.TRUE
        assert intel.kev_date_added == "2024-03-29"
        assert report.sources["epss"].usable

    def test_exploit_sources_are_traceable(self, config, tmp_path):
        """출처를 댈 수 없는 exploit 주장은 리포트에 쓰지 않는다."""
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)

        assert finding.intel.exploit_available is Ternary.TRUE
        refs = {(s.source, s.ref) for s in finding.intel.exploit_sources}
        assert ("exploit_db", "EDB-52128") in refs
        assert ("metasploit", "exploit/linux/local/xz_backdoor") in refs

    def test_metasploit_module_means_weaponized(self, config, tmp_path):
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)
        assert finding.intel.exploit_maturity is ExploitMaturity.WEAPONIZED

    def test_exploitdb_only_means_public_poc(self, config, tmp_path):
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-21538")], nvd_budget=0)
        assert finding.intel.exploit_maturity is ExploitMaturity.PUBLIC_POC
        assert finding.intel.exploit_available is Ternary.TRUE

    def test_kev_and_exploit_are_independent_signals(self, config, tmp_path):
        """CVE-2024-21538은 공개 PoC는 있으나 KEV에는 없다."""
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-21538")], nvd_budget=0)
        assert finding.intel.kev is Ternary.FALSE
        assert finding.intel.exploit_available is Ternary.TRUE

    def test_absent_from_all_sources_is_false_not_unknown(self, config, tmp_path):
        """소스는 읽었는데 그 CVE가 없으면 '없음'으로 확정할 수 있다."""
        seed_caches(config)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-1999-0001")], nvd_budget=0)
        assert finding.intel.kev is Ternary.FALSE
        assert finding.intel.exploit_available is Ternary.FALSE
        assert finding.intel.epss is None          # EPSS는 목록에 없으면 값이 없는 것
        assert finding.intel.epss_snapshot_date == "2026-08-18"


class TestUnavailableSourcesStayUnknown:
    def test_no_kev_source_leaves_kev_unknown(self, config, tmp_path):
        seed_caches(config, kev=False)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), report = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)
        assert finding.intel.kev is Ternary.UNKNOWN     # '등재 안 됨'이 아니다
        assert not report.sources["kev"].usable

    def test_no_exploit_sources_leave_exploit_unknown(self, config, tmp_path):
        seed_caches(config, edb=False, msf=False)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)
        assert finding.intel.exploit_available is Ternary.UNKNOWN
        assert finding.intel.exploit_maturity is ExploitMaturity.UNKNOWN

    def test_no_epss_source_leaves_score_none(self, config, tmp_path):
        seed_caches(config, epss=False)
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        (finding,), _ = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)
        assert finding.intel.epss is None          # 0.0으로 채우지 않는다
        assert finding.intel.epss_snapshot_date == ""

    def test_offline_with_no_cache_reports_offline_state(self, config, tmp_path):
        enricher = Enricher(config, Store(tmp_path / "t.db"))
        _, report = enricher.enrich([make_finding("CVE-2024-3094")], nvd_budget=0)
        assert all(s.state == "offline" for s in report.sources.values())


def test_enrichment_report_counts_matches(config, tmp_path):
    seed_caches(config)
    enricher = Enricher(config, Store(tmp_path / "t.db"))
    _, report = enricher.enrich(
        [make_finding("CVE-2024-3094"), make_finding("CVE-1999-0001")], nvd_budget=0
    )
    assert report.sources["epss"].entries == 2
    assert report.sources["epss"].matched == 1        # 2건 중 1건만 EPSS에 있다
    assert report.sources["kev"].matched == 1
