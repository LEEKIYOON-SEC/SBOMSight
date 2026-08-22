"""Grype 가 판정의 유일한 출처라는 것을 고정한다.

> 우리는 grype 라는 걸 신뢰하겠다고 선택한 거고 틀려도 감수하겠다는 건데
> 그 외의 문제들로 grype 의 결과가 틀리면 안 되는 거지

Grype 가 틀리면 그것은 Grype 의 오류이고 감수한다. **우리 코드 때문에 결과가
달라지는 것은 감수 대상이 아니다.** 여기 있는 테스트는 그 경계를 지킨다.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from core.config import Config
from core.enrich import Enricher
from core.models import ScanResult, Ternary
from core.normalize import normalize_grype_report
from core.report import ReportBuilder
from core.ruleengine import RuleEngine
from core.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"

# 보강 소스가 실제로 값을 채우도록 캐시를 심는다. 아무것도 채우지 않으면
# "보강이 판정을 바꾸지 않는다"는 것이 공허하게 참이 된다.
EPSS_CSV = (
    b"#model_version:v2025.03.14,score_date:2026-08-18T00:00:00+0000\n"
    b"cve,epss,percentile\n"
    b"CVE-2024-3094,0.9134,0.9991\n"
    b"CVE-2023-45853,0.4200,0.8800\n"
    b"CVE-2024-2511,0.0043,0.5120\n"
    b"CVE-2024-21538,0.1500,0.9300\n"
    b"CVE-2024-35195,0.0009,0.2130\n"
)
KEV_JSON = json.dumps({
    "catalogVersion": "2026.08.18",
    "vulnerabilities": [
        {"cveID": "CVE-2024-3094", "dateAdded": "2024-03-29",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2023-45853", "dateAdded": "2025-01-02",
         "knownRansomwareCampaignUse": "Known"},
    ],
}).encode()
EDB_CSV = (
    b"id,file,description,date_published,author,type,platform,port,date_added,"
    b"date_updated,verified,codes,tags,aliases,screenshot_url,application_url,"
    b"source_url\n"
    b"52128,exploits/linux/local/52128.py,XZ backdoor,2024-04-01,x,local,linux,,"
    b"2024-04-01,2024-04-01,1,CVE-2024-3094,,,,,\n"
)
MSF_JSON = json.dumps({
    "exploit/linux/local/xz_backdoor": {
        "name": "XZ Utils Backdoor RCE",
        "fullname": "exploit/linux/local/xz_backdoor",
        "references": ["CVE-2024-3094"],
    }
}).encode()


def _verdict_set(result: ScanResult) -> set[tuple]:
    """Grype 가 답한 것들. 이 집합이 보강 전후로 같아야 한다.

    `(CVE, 패키지명, 설치 버전, 수정 버전, 수정 상태, 취약 여부)` — 판정을
    이루는 값 전부다. 하나라도 달라지면 우리가 Grype 를 덮어쓴 것이다.
    """
    return {
        (
            f.intel.cve,
            f.installed.name,
            f.installed.version,
            f.advisory.fixed_version,
            f.advisory.fix_state.value,
            f.fix.is_vulnerable.value if f.fix else "",
            f.fix.update_available.value if f.fix else "",
        )
        for f in result.findings
    }


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path / "data"
    cfg.ensure_dirs()
    cfg.offline = True
    cfg.collect_exploitdb = True
    cfg.collect_metasploit = True
    return cfg


@pytest.fixture
def seeded(config):
    """오프라인 폴백 경로로 실제 값이 채워지도록 캐시를 심는다."""
    from core.enrich import EpssSource, ExploitDbSource, KevSource, MetasploitSource

    for source, raw in (
        (EpssSource(config), gzip.compress(EPSS_CSV)),
        (KevSource(config), KEV_JSON),
        (ExploitDbSource(config), EDB_CSV),
        (MetasploitSource(config), MSF_JSON),
    ):
        index, snapshot = source.parse(raw)
        source._write_cache(index, snapshot)
    return config


def _scan() -> ScanResult:
    return normalize_grype_report(
        json.loads(FIXTURE.read_text(encoding="utf-8")),
        scan_id="authority", sbom_filename="s.json",
    )


class TestEnrichmentNeverChangesTheVerdict:
    def test_the_verdict_set_is_identical_with_and_without_enrichment(self, seeded, tmp_path):
        """요구의 핵심. 보강을 켜고 끈 두 결과의 판정 집합이 **완전히** 같아야 한다."""
        without = _scan()
        with_enrich, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich(without.findings)

        assert _verdict_set(ScanResult(metadata=without.metadata, findings=with_enrich)) \
            == _verdict_set(without)

    def test_enrichment_actually_filled_something(self, seeded, tmp_path):
        """위 테스트가 공허하게 참이 아님을 보인다 — 보강이 실제로 값을 채웠다."""
        enriched, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich(_scan().findings)
        assert any(f.intel.epss is not None for f in enriched)
        assert any(f.intel.kev is Ternary.TRUE for f in enriched)
        assert any(f.intel.exploit_available is Ternary.TRUE for f in enriched)

    def test_cvss_is_never_overwritten(self, seeded, tmp_path):
        """CVSS 는 Grype 값이 우선이다. 보강이 덮어쓰는 경로가 있으면 안 된다."""
        before = {f.intel.cve: (f.intel.cvss_score, f.intel.cvss_vector, f.intel.severity)
                  for f in _scan().findings}
        enriched, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich(_scan().findings)
        after = {f.intel.cve: (f.intel.cvss_score, f.intel.cvss_vector, f.intel.severity)
                 for f in enriched}
        assert after == before

    def test_finding_count_is_unchanged(self, seeded, tmp_path):
        """보강이 항목을 늘리거나 줄이지 않는다."""
        original = _scan().findings
        enriched, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich(original)
        assert len(enriched) == len(original)

    def test_grype_supplied_epss_wins_over_the_external_snapshot(self, seeded, tmp_path):
        """Grype 가 준 값이 있으면 외부 스냅샷이 덮어쓰지 않는다.

        판정의 근간과 같은 출처에서 온 값을 다른 날짜의 스냅샷으로 갈아치우면
        한 화면 안에 두 시점이 섞인다.
        """
        import dataclasses

        scan = _scan()
        target = scan.findings[0]
        pinned = dataclasses.replace(
            target,
            intel=dataclasses.replace(target.intel, epss=0.5, epss_snapshot_date="2026-08-22"),
        )
        enriched, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich([pinned])
        assert enriched[0].intel.epss == 0.5
        assert enriched[0].intel.epss_snapshot_date == "2026-08-22"

    def test_grype_supplied_kev_wins_too(self, seeded, tmp_path):
        import dataclasses

        scan = _scan()
        target = next(f for f in scan.findings if f.intel.cve == "CVE-2024-3094")
        pinned = dataclasses.replace(
            target, intel=dataclasses.replace(target.intel, kev=Ternary.FALSE),
        )
        enriched, _ = Enricher(seeded, Store(tmp_path / "t.db")).enrich([pinned])
        # 외부 KEV 카탈로그에는 등재되어 있지만 Grype 가 아니라고 했으므로 그대로 둔다.
        assert enriched[0].intel.kev is Ternary.FALSE


class TestPriorityJudgementUsesOnlyPublicSignals:
    def test_rule_engine_does_not_touch_the_verdict_fields(self, tmp_path):
        """우선순위 판정은 표시용 등급을 붙일 뿐 Grype 의 답을 건드리지 않는다."""
        scan = _scan()
        engine = RuleEngine.from_config()
        judged = ScanResult(metadata=scan.metadata, findings=tuple(engine.apply(scan.findings)))
        assert _verdict_set(judged) == _verdict_set(scan)

    def test_every_finding_is_vulnerable_because_grype_detected_it(self):
        """표에 있는 것은 전부 Grype 가 취약하다고 탐지한 것이다.

        예전에는 우리 비교자로 다시 계산해 `is_vulnerable` 을 독립 산출했고,
        비교자에 흠이 하나만 있어도 Grype 가 탐지한 항목이 "취약 아니오"로 떴다.
        """
        for finding in _scan().findings:
            assert finding.fix.is_vulnerable is Ternary.TRUE


class TestReportDoesNotAlterTheVerdict:
    def test_package_grouping_preserves_every_finding(self):
        """패키지로 묶어도 항목이 사라지지 않는다."""
        scan = _scan()
        engine = RuleEngine.from_config()
        judged = ScanResult(metadata=scan.metadata, findings=tuple(engine.apply(scan.findings)))
        report = ReportBuilder(engine=engine).build(judged)

        grouped = [item for group in report.packages for item in group.findings]
        assert len(grouped) == len(report.findings) == len(scan.findings)
        assert {i.cve for i in grouped} == {f.intel.cve for f in scan.findings}

    def test_target_version_is_the_highest_not_the_first(self):
        """묶음의 목표 버전은 전부를 해소하는 **가장 높은** 것이어야 한다.

        가장 낮은 것으로 올리면 나머지 CVE 가 남는데, 보고서는 해소됐다고 말한다.
        """
        from core.report import _highest_version

        assert _highest_version(["1.0.2", "1.0.10", "1.0.9"], "semver") == "1.0.10"
        assert _highest_version(["1:3.0.7-24.el9", "1:3.0.7-27.el9_4"], "rpm") \
            == "1:3.0.7-27.el9_4"

    def test_unorderable_versions_do_not_get_promoted(self):
        """비교자가 순서를 판단하지 못하면 바꾸지 않는다.

        모르는 채로 더 높다고 단정하는 것이 가장 나쁘다.
        """
        from core.report import _highest_version

        assert _highest_version(["not-a-version", "also-not"], "semver") == "not-a-version"
