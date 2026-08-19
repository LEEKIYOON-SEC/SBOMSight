"""Rule Engine 테스트.

지키려는 계약:
  1. 판정은 결정론적이고, 어떤 룰이 왜 발화했는지가 함께 나온다.
  2. 데이터가 없는 것과 값이 낮은 것을 구분한다.
  3. KEV와 Exploit은 독립 신호로 평가된다.
  4. 조직별 오버라이드가 판정을 바꾸고, 그 사실이 정책 해시에 남는다.
"""

import json

import pytest

from core.fixanalysis import analyze
from core.models import (
    AdvisoryPackage,
    ExploitMaturity,
    FixState,
    Finding,
    InstalledPackage,
    Priority,
    Severity,
    Ternary,
    VulnIntel,
)
from core.policy import load as load_policy
from core.ruleengine import RuleEngine, sort_key

DEFAULT_POLICY = "rules/priority.json"


@pytest.fixture(scope="module")
def engine():
    return RuleEngine(load_policy(DEFAULT_POLICY))


def make_finding(
    *,
    cvss=None,
    epss=None,
    kev=Ternary.FALSE,
    exploit=Ternary.FALSE,
    maturity=ExploitMaturity.NONE,
    fixed="2.0.0",
    fix_state=FixState.UNKNOWN,
    installed="1.0.0",
    ecosystem="npm",
    snapshot="2099-01-01",
):
    pkg = InstalledPackage(name="pkg", version=installed, type=ecosystem)
    adv = AdvisoryPackage(
        advisory_package="pkg",
        advisory_ecosystem=ecosystem,
        affected_version_range=f"<{fixed}" if fixed else "*",
        fixed_version=fixed,
        fix_state=fix_state,
    )
    intel = VulnIntel(
        cve="CVE-2024-0001",
        severity=Severity.UNKNOWN,
        cvss_score=cvss,
        epss=epss,
        kev=kev,
        exploit_available=exploit,
        exploit_maturity=maturity,
        epss_snapshot_date=snapshot,
        kev_snapshot_date=snapshot,
    )
    return Finding(installed=pkg, advisory=adv, intel=intel, fix=analyze(pkg, adv))


class TestPriorityLevels:
    def test_kev_alone_reaches_p0(self, engine):
        # KEV는 실제 악용이 확인된 것이므로 CVSS와 무관하게 즉시 검토 대상이다.
        verdict = engine.evaluate(make_finding(cvss=4.0, kev=Ternary.TRUE))
        assert verdict.priority is Priority.P0
        assert [r.name for r in verdict.fired_rules] == ["kev_listed"]

    def test_high_epss_with_high_cvss_reaches_p0(self, engine):
        verdict = engine.evaluate(make_finding(cvss=7.5, epss=0.6))
        assert verdict.priority is Priority.P0
        assert {r.name for r in verdict.fired_rules} == {"epss_high", "cvss_high"}

    def test_weaponized_exploit_with_high_cvss_reaches_p0(self, engine):
        verdict = engine.evaluate(
            make_finding(cvss=8.0, exploit=Ternary.TRUE, maturity=ExploitMaturity.WEAPONIZED)
        )
        assert verdict.priority is Priority.P0

    def test_critical_cvss_alone_reaches_p1(self, engine):
        verdict = engine.evaluate(make_finding(cvss=9.8))
        assert verdict.priority is Priority.P1
        assert [r.name for r in verdict.fired_rules] == ["cvss_critical"]

    def test_public_poc_with_high_cvss_reaches_p1(self, engine):
        verdict = engine.evaluate(
            make_finding(cvss=7.5, exploit=Ternary.TRUE, maturity=ExploitMaturity.PUBLIC_POC)
        )
        assert verdict.priority is Priority.P1

    def test_high_cvss_alone_is_p2(self, engine):
        verdict = engine.evaluate(make_finding(cvss=7.5))
        assert verdict.priority is Priority.P2

    def test_everything_else_is_p3(self, engine):
        verdict = engine.evaluate(make_finding(cvss=4.0, epss=0.01))
        assert verdict.priority is Priority.P3
        assert verdict.fired_rules == ()


class TestKevAndExploitAreIndependent:
    """KEV 등재와 공개 exploit 존재는 다른 개념이다."""

    def test_kev_without_public_exploit(self, engine):
        verdict = engine.evaluate(
            make_finding(cvss=6.0, kev=Ternary.TRUE, exploit=Ternary.FALSE, maturity=ExploitMaturity.NONE)
        )
        assert verdict.priority is Priority.P0        # KEV만으로 P0
        assert "unknown_exploit" not in verdict.flags  # exploit은 '없음'으로 확인됨

    def test_public_exploit_without_kev(self, engine):
        verdict = engine.evaluate(
            make_finding(cvss=7.5, kev=Ternary.FALSE, exploit=Ternary.TRUE,
                         maturity=ExploitMaturity.PUBLIC_POC)
        )
        # KEV가 아니므로 P0는 아니지만, 공개 PoC 신호로 P1까지 올라간다.
        assert verdict.priority is Priority.P1
        assert {r.name for r in verdict.fired_rules} == {"exploit_public_poc", "cvss_high"}


class TestMissingDataIsNotLowRisk:
    """'데이터가 없다'와 '값이 낮다'를 구분한다."""

    def test_missing_epss_sets_flag_and_does_not_fire_signal(self, engine):
        verdict = engine.evaluate(make_finding(cvss=7.5, epss=None))
        assert "unknown_epss" in verdict.flags
        assert "epss_high" not in {r.name for r in verdict.fired_rules}

    def test_unknown_kev_sets_flag(self, engine):
        verdict = engine.evaluate(make_finding(cvss=7.5, kev=Ternary.UNKNOWN))
        assert "unknown_kev" in verdict.flags
        assert verdict.priority is Priority.P2   # KEV 미확인이 P0을 만들지는 않는다

    def test_unknown_exploit_sets_flag(self, engine):
        verdict = engine.evaluate(
            make_finding(cvss=7.5, exploit=Ternary.UNKNOWN, maturity=ExploitMaturity.UNKNOWN)
        )
        assert "unknown_exploit" in verdict.flags

    def test_missing_cvss_sets_flag(self, engine):
        verdict = engine.evaluate(make_finding(cvss=None))
        assert "no_cvss" in verdict.flags
        assert verdict.priority is Priority.P3


class TestFlags:
    def test_no_fix_available(self, engine):
        verdict = engine.evaluate(make_finding(cvss=9.8, fixed="", fix_state=FixState.WONT_FIX))
        assert "no_fix_available" in verdict.flags
        # 플래그는 우선순위와 독립이다 — 패치 못 한다고 등급이 내려가지 않는다.
        assert verdict.priority is Priority.P1

    def test_update_available(self, engine):
        verdict = engine.evaluate(make_finding(cvss=5.0, installed="1.0.0", fixed="2.0.0"))
        assert "update_available" in verdict.flags

    def test_vulnerability_unconfirmed_when_version_uncomparable(self, engine):
        verdict = engine.evaluate(make_finding(cvss=5.0, installed="git-abcdef", fixed="2.0.0"))
        assert "vulnerability_unconfirmed" in verdict.flags

    def test_stale_snapshot_flagged(self, engine):
        verdict = engine.evaluate(make_finding(cvss=5.0, snapshot="2020-01-01"), stale_days=7)
        assert "stale_snapshot" in verdict.flags

    def test_fresh_snapshot_not_flagged(self, engine):
        verdict = engine.evaluate(make_finding(cvss=5.0, snapshot="2099-01-01"), stale_days=7)
        assert "stale_snapshot" not in verdict.flags


class TestExplanations:
    def test_fired_rules_carry_numbers(self, engine):
        """근거에 숫자가 없으면 사람이 판정을 검증할 수 없다."""
        verdict = engine.evaluate(make_finding(cvss=9.8, epss=0.6))
        explains = {r.name: r.explain for r in verdict.fired_rules}
        assert "0.6 ≥ 0.5" in explains["epss_high"]
        assert "9.8 ≥ 7" in explains["cvss_high"]

    def test_policy_identity_is_recorded(self, engine):
        verdict = engine.evaluate(make_finding(cvss=9.8))
        assert verdict.policy_version == "1"
        assert len(verdict.policy_sha256) == 64


class TestOrganizationOverride:
    def test_override_changes_verdict_and_hash(self, tmp_path, engine):
        override = tmp_path / "priority.local.json"
        override.write_text(
            json.dumps({"version": "1-org", "signals": {"epss_high": {"field": "epss", "op": ">=", "value": 0.1,
                                                                     "label": "EPSS 높음(사내)"}}}),
            encoding="utf-8",
        )
        org_engine = RuleEngine(load_policy(DEFAULT_POLICY, override))

        finding = make_finding(cvss=7.5, epss=0.2)
        assert engine.evaluate(finding).priority is Priority.P1        # 기본: 0.2 < 0.5
        assert org_engine.evaluate(finding).priority is Priority.P0    # 사내: 0.2 >= 0.1

        assert org_engine.policy.version == "1-org"
        assert org_engine.policy.sha256 != engine.policy.sha256
        assert "priority.local.json" in org_engine.policy.sources

    def test_missing_override_file_is_fine(self, tmp_path):
        loaded = load_policy(DEFAULT_POLICY, tmp_path / "does-not-exist.json")
        assert loaded.sources == ("priority.json",)


def test_apply_fills_verdicts_without_mutating_input(engine):
    findings = (make_finding(cvss=9.8), make_finding(cvss=3.0))
    assert all(f.verdict is None for f in findings)
    result = engine.apply(findings)
    assert [f.verdict.priority for f in result] == [Priority.P1, Priority.P3]
    assert all(f.verdict is None for f in findings)   # 원본은 그대로


def test_sort_key_orders_by_priority_then_severity(engine):
    findings = engine.apply(
        (
            make_finding(cvss=5.0),
            make_finding(cvss=9.9, kev=Ternary.TRUE),
            make_finding(cvss=9.8),
            make_finding(cvss=7.5),
        )
    )
    ordered = [f.verdict.priority for f in sorted(findings, key=sort_key)]
    assert ordered == [Priority.P0, Priority.P1, Priority.P2, Priority.P3]
