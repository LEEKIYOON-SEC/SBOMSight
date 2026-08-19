"""보고서 생성 테스트.

M3의 수용 기준: **AI 없이도 보고서가 완결된다.** ②기술적 위험성,
④대응 필요성 분석, ⑤권고사항이 룰만으로 채워져야 하고, 근거 배지와
Reference가 모든 항목에 붙어야 한다.
"""

import json
from pathlib import Path

import pytest

from core.config import Config
from core.fixanalysis import analyze
from core.models import (
    AdvisoryPackage,
    ExploitMaturity,
    ExploitSource,
    FixState,
    Finding,
    InstalledPackage,
    Priority,
    ScanMetadata,
    ScanResult,
    Severity,
    Ternary,
    VulnIntel,
)
from core.normalize import normalize_grype_report
from core.render import to_html, to_markdown
from core.report import Narrative, ReportBuilder
from core.ruleengine import RuleEngine

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture(scope="module")
def scan_result():
    result = normalize_grype_report(json.loads(FIXTURE.read_text()), scan_id="s1", sbom_filename="a.json")
    engine = RuleEngine.from_config()
    return ScanResult(
        metadata=result.metadata,
        findings=engine.apply(result.findings),
        policy={"label": "priority.json v1 (sha256:abc123456789)"},
    )


@pytest.fixture(scope="module")
def report(scan_result):
    return ReportBuilder().build(scan_result)


def item_for(report, cve):
    return next(i for i in report.findings if i.cve == cve)


class TestCompleteWithoutAi:
    """AI 없이 모든 절이 채워지는가 — M3의 수용 기준."""

    def test_report_is_marked_as_rule_generated(self, report):
        assert report.ai_used is False
        assert all(i.narrative_source == "rule" for i in report.findings)

    def test_every_finding_has_all_six_sections(self, report):
        assert report.findings
        for item in report.findings:
            assert item.overview["cve"]
            assert item.technical_risk["narrative"]         # ②
            assert item.exploitability["narrative"]         # ③
            assert item.response_rationale["narrative"]     # ④
            assert item.recommendation.action               # ⑤
            assert item.references                          # ⑥

    def test_technical_risk_derived_from_cvss_vector(self, report):
        item = item_for(report, "CVE-2024-3094")
        assert "네트워크를 통해 인증이나 사용자 조작 없이" in item.technical_risk["narrative"]
        assert "공격 경로: 네트워크" in item.technical_risk["preconditions"]
        assert any("원격 코드 실행" in i for i in item.technical_risk["impact_types"])

    def test_response_rationale_cites_fired_rules(self, report):
        # 이 픽스처는 위협정보 보강 없이 판정되므로 CVSS만으로 등급이 정해진다.
        # 그래도 근거는 숫자와 함께 문장에 실려야 한다.
        item = item_for(report, "CVE-2024-3094")
        assert "CVSS Critical (10 ≥ 9)" in item.response_rationale["narrative"]
        assert [r["name"] for r in item.response_rationale["fired_rules"]] == ["cvss_critical"]

    def test_rationale_explains_default_grade_when_nothing_fired(self, report):
        item = item_for(report, "CVE-2024-2511")   # CVSS 5.3, 상향 조건 없음
        assert "상향 조건에 해당하는 신호가 관측되지 않아" in item.response_rationale["narrative"]

    def test_recommendation_comes_from_playbook_not_ai(self, report):
        item = item_for(report, "CVE-2024-3094")
        rec = item.recommendation
        assert rec.ecosystem == "rpm"
        assert any("dnf" in s for s in rec.online_steps)
        assert any("dnf download --resolve --alldeps" in s for s in rec.airgapped_steps)
        assert any("rpm -K" in s for s in rec.airgapped_steps)


class TestEvidenceBadge:
    def test_badge_shows_numbers_not_just_labels(self, report):
        badge = item_for(report, "CVE-2024-3094").badge
        assert "10" in badge.cvss and "CVSS:3.1/" in badge.cvss
        assert badge.fixed_version == "5.6.2"

    def test_badge_records_verdict_and_policy(self, report):
        badge = item_for(report, "CVE-2024-3094").badge
        assert badge.verdict.startswith("P1")
        assert "cvss_critical" in badge.verdict
        assert "sha256:" in badge.policy

    def test_unknown_values_say_unknown_not_zero(self, report):
        # 픽스처에는 EPSS/KEV 보강이 없다 — 0이나 NO가 아니라 '미확인'이어야 한다.
        badge = item_for(report, "CVE-2024-3094").badge
        assert badge.epss == "미확인"
        assert badge.kev == "미확인"
        assert badge.exploit == "미확인"


class TestLocalAnalysisIsSeparated:
    def test_local_section_is_marked_not_transmitted(self, report):
        local = item_for(report, "CVE-2024-3094").local_analysis
        assert local["ai_transmitted"] is False

    def test_local_section_holds_installed_version_and_fix_analysis(self, report):
        local = item_for(report, "CVE-2024-3094").local_analysis
        assert local["installed_version"] == "5.6.0-2.el9"
        assert local["locations"] == ["/var/lib/rpm/rpmdb.sqlite"]
        fa = local["fix_analysis"]
        assert fa["is_vulnerable"] == "true"
        assert fa["update_available"] == "true"
        assert fa["comparator"] == "rpm"

    def test_installed_version_never_appears_in_public_sections(self, report):
        """설치 버전은 로컬 영역 밖으로 새면 안 된다."""
        item = item_for(report, "CVE-2024-3094")
        public = json.dumps(
            [item.overview, item.technical_risk, item.exploitability, item.response_rationale],
            ensure_ascii=False,
        )
        assert "5.6.0-2.el9" not in public
        assert "/var/lib/rpm" not in public


class TestNoFixAvailable:
    def test_no_fix_swaps_patch_steps_for_mitigations(self, report):
        rec = item_for(report, "CVE-2023-45853").recommendation
        assert rec.has_fix is False
        assert rec.online_steps == ()
        assert rec.airgapped_steps == ()
        assert rec.mitigations
        assert "공개된 수정 버전이 없어" in rec.action

    def test_fix_available_does_not_show_mitigations(self, report):
        """패치가 가능한데 완화책을 나란히 놓으면 '패치 안 해도 된다'로 읽힌다."""
        rec = item_for(report, "CVE-2024-3094").recommendation
        assert rec.has_fix is True
        assert rec.mitigations == ()

    def test_no_fix_flag_is_explained_in_rationale(self, report):
        item = item_for(report, "CVE-2023-45853")
        assert "완화 방안 검토가 함께 필요하다" in item.response_rationale["narrative"]


class TestReferences:
    def test_nvd_and_epss_always_present_for_cve(self, report):
        refs = item_for(report, "CVE-2024-3094").references
        sources = {r["source"] for r in refs}
        assert "NVD" in sources
        assert "FIRST EPSS" in sources

    def test_vendor_advisory_is_labelled(self, report):
        refs = item_for(report, "CVE-2024-2511").references
        assert any(r["source"] == "Red Hat Advisory" for r in refs)


class TestAiNarrativeOverlay:
    def test_ai_narrative_replaces_rule_text_and_is_marked(self, scan_result):
        report = ReportBuilder().build(
            scan_result,
            narratives={
                "CVE-2024-3094": Narrative(
                    technical_risk="AI가 쓴 기술적 위험성 서술.",
                    response_rationale="AI가 쓴 대응 필요성 서술.",
                    source="ai",
                )
            },
        )
        item = item_for(report, "CVE-2024-3094")
        assert item.technical_risk["narrative"] == "AI가 쓴 기술적 위험성 서술."
        assert item.narrative_source == "ai"
        assert report.ai_used is True

        # AI가 없는 항목은 여전히 룰 문장으로 채워진다.
        other = item_for(report, "CVE-2024-2511")
        assert other.narrative_source == "rule"
        assert other.technical_risk["narrative"]

    def test_priority_never_comes_from_ai(self, scan_result):
        """AI 응답이 우선순위를 바꿀 수 없다 — Narrative에는 그 자리가 없다."""
        assert "priority" not in Narrative.__dataclass_fields__
        report = ReportBuilder().build(
            scan_result, narratives={"CVE-2024-3094": Narrative(source="ai")}
        )
        assert item_for(report, "CVE-2024-3094").priority is Priority.P1  # 룰 판정 그대로


class TestSummary:
    def test_summary_counts(self, report):
        s = report.summary
        assert s["total"] == 5
        assert sum(s["by_priority"].values()) == 5
        assert s["affected_packages"] == 5
        assert s["no_fix_available"] == 1

    def test_summary_separates_confirmed_from_unconfirmed(self, report):
        s = report.summary
        assert "vulnerable_confirmed" in s
        assert "vulnerable_unconfirmed" in s


class TestRendering:
    def test_markdown_has_disclaimer_and_all_sections(self, report):
        text = to_markdown(report)
        assert "보안담당자가 판단한다" in text
        for heading in ("① 취약점 개요", "② 기술적 위험성", "③ 악용 가능성",
                        "④ 대응 필요성 분석", "⑤ 권고사항", "⑥ 근거 및 Reference"):
            assert heading in text
        assert "[로컬 분석 정보] · AI 미전달" in text

    def test_markdown_marks_rule_vs_ai(self, report):
        assert "AI 미사용 (룰 기반)" in to_markdown(report)

    def test_html_renders_and_escapes(self, report):
        page = to_html(report)
        assert page.startswith("<!doctype html>")
        assert "AI 미전달" in page
        assert "<script>" not in page          # 설명문에 스크립트가 섞여도 이스케이프된다
        assert "폐쇄망" in page

    def test_html_escapes_hostile_description(self, scan_result):
        """SBOM·advisory 문자열이 그대로 HTML에 들어가면 안 된다."""
        hostile = Finding(
            installed=InstalledPackage(name="p", version="1.0", type="npm"),
            advisory=AdvisoryPackage(advisory_package="p", advisory_ecosystem="npm", fixed_version="2.0"),
            intel=VulnIntel(cve="CVE-2024-9999", description="<script>alert(1)</script>"),
        )
        engine = RuleEngine.from_config()
        result = ScanResult(metadata=scan_result.metadata, findings=engine.apply((hostile,)))
        page = to_html(ReportBuilder().build(result))
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page
