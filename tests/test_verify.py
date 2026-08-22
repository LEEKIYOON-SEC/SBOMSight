"""Grype 원본 ↔ 우리 결과 대조.

이 도구는 **Grype 를 신뢰하기로 선택한 도구**다. Grype 가 틀리면 그것은 Grype 의
오류이고 감수한다. 우리 코드 때문에 결과가 달라지는 것은 감수 대상이 아니다.

말로 하는 약속은 검증할 수 없으므로 여기서 벡터로 고정한다. 정규화·보강·정렬·
저장 어디에서도 매치가 사라지거나 값이 바뀌면 이 테스트가 깨져야 한다.
"""

import json
from pathlib import Path

import pytest

from core.enrich import Enricher
from core.normalize import normalize_grype_report
from core.ruleengine import RuleEngine
from core.verify import verify

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture
def raw():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def result(raw):
    return normalize_grype_report(raw, scan_id="v-1")


class TestFaithfulNormalisation:
    def test_our_result_matches_grype_exactly(self, raw, result):
        report = verify(raw, result)
        assert report.ok, "\n".join(str(m) for m in report.mismatches)

    def test_every_grype_match_is_accounted_for(self, raw, result):
        """탐지 + 합침 + 미전환 = Grype 매치 수. 조용히 사라지는 것이 없어야 한다."""
        report = verify(raw, result)
        assert report.our_findings + report.merged + report.dropped == report.grype_matches

    def test_metadata_records_the_grype_match_count(self, raw, result):
        assert result.metadata.grype_match_count == len(raw["matches"])
        assert result.metadata.accounted is True


class TestPriorityAndSortingDoNotAlterResults:
    def test_rule_engine_does_not_change_the_finding_set(self, raw, result):
        """우선순위를 매긴다고 탐지 결과가 달라지면 안 된다."""
        scored = RuleEngine.from_config().apply(result.findings)
        assert len(scored) == len(result.findings)
        report = verify(raw, result.__class__(metadata=result.metadata, findings=tuple(scored)))
        assert report.ok, "\n".join(str(m) for m in report.mismatches)


class TestEnrichmentDoesNotAlterResults:
    def test_offline_enrichment_leaves_grype_values_intact(self, raw, result, tmp_path, monkeypatch):
        """보강은 빈 칸만 채운다. Grype 가 준 값은 건드리지 않는다.

        사용자 요구를 그대로 옮긴 테스트다: "추가 정보 때문에 Grype 결과가
        틀리면 안 된다."
        """
        monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SBOMSIGHT_OFFLINE", "1")
        import core.config

        config = core.config.get_config(refresh=True)
        config.ensure_dirs()

        from core.store import Store

        enriched, _ = Enricher(config, Store(config.db_path)).enrich(result.findings)
        after = result.__class__(metadata=result.metadata, findings=tuple(enriched))

        report = verify(raw, after)
        assert report.ok, "\n".join(str(m) for m in report.mismatches)

    def test_enrichment_never_touches_cvss_or_fix(self, raw, result, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOMSIGHT_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SBOMSIGHT_OFFLINE", "1")
        import core.config

        config = core.config.get_config(refresh=True)
        config.ensure_dirs()
        from core.store import Store

        before = {f.key: f for f in result.findings}
        enriched, _ = Enricher(config, Store(config.db_path)).enrich(result.findings)

        for finding in enriched:
            original = before[finding.key]
            assert finding.intel.cvss_score == original.intel.cvss_score
            assert finding.intel.severity == original.intel.severity
            assert finding.advisory == original.advisory      # fixed_version · fix_state 포함
            assert finding.installed == original.installed


class TestMismatchDetection:
    """대조기가 실제로 어긋남을 잡아내는지. 잡지 못하면 통과는 의미가 없다."""

    def test_detects_a_missing_finding(self, raw, result):
        stripped = result.__class__(
            metadata=result.metadata, findings=result.findings[1:]
        )
        report = verify(raw, stripped)
        assert not report.ok
        assert any(m.kind == "누락" for m in report.mismatches)

    def test_detects_a_changed_fixed_version(self, raw, result):
        import dataclasses

        first = result.findings[0]
        tampered = dataclasses.replace(
            first, advisory=dataclasses.replace(first.advisory, fixed_version="9.9.9")
        )
        report = verify(
            raw,
            result.__class__(metadata=result.metadata,
                             findings=(tampered, *result.findings[1:])),
        )
        assert not report.ok
        assert any(m.kind == "수정 버전 불일치" for m in report.mismatches)

    def test_detects_a_changed_fix_state(self, raw, result):
        import dataclasses

        from core.models import FixState

        first = result.findings[0]
        other = (FixState.WONT_FIX if first.advisory.fix_state is not FixState.WONT_FIX
                 else FixState.NOT_FIXED)
        tampered = dataclasses.replace(
            first, advisory=dataclasses.replace(first.advisory, fix_state=other)
        )
        report = verify(
            raw,
            result.__class__(metadata=result.metadata,
                             findings=(tampered, *result.findings[1:])),
        )
        assert not report.ok
        assert any(m.kind == "수정 상태 불일치" for m in report.mismatches)

    def test_detects_accounting_gap(self, raw, result):
        """합침·미전환으로 설명되지 않는 감소는 회계 불일치로 잡힌다."""
        import dataclasses

        thinned = result.__class__(
            metadata=dataclasses.replace(result.metadata, merged_count=0, dropped=()),
            findings=result.findings[:-1],
        )
        report = verify(raw, thinned)
        assert any(m.kind == "회계 불일치" for m in report.mismatches)


class TestAliasLookup:
    def test_finds_us_by_the_id_grype_reported(self, raw, result):
        """Grype 의 primary 가 RHSA·GHSA 여도 그 ID 로 되찾을 수 있어야 한다.

        우리는 관련 CVE 를 대표로 올리고 원래 ID 를 별칭에 남긴다. 별칭을 잃으면
        Grype 결과와 대조할 방법이 사라진다.
        """
        grype_ids = {str(m["vulnerability"]["id"]) for m in raw["matches"]}
        ours = set()
        for finding in result.findings:
            ours.add(finding.intel.cve)
            ours.update(finding.intel.aliases)
        assert grype_ids <= ours, f"Grype 가 보고한 ID 를 잃었다: {grype_ids - ours}"
