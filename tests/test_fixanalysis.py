"""FixAnalysis(로컬 전용 판정) 테스트.

가장 중요한 계약: **판단할 수 없을 때 unknown을 낸다.** 비표준 버전 문자열을
만났을 때 "취약하지 않음"이라 답하면 그 취약점은 조용히 리포트에서 사라진다.
"""

from core.fixanalysis import analyze
from core.models import AdvisoryPackage, FixState, InstalledPackage, Ternary, VersionGap


def make(installed_version, *, ecosystem="rpm", affected="", fixed="", fix_state=FixState.UNKNOWN):
    return analyze(
        InstalledPackage(name="pkg", version=installed_version, type=ecosystem),
        AdvisoryPackage(
            advisory_package="pkg",
            advisory_ecosystem=ecosystem,
            affected_version_range=affected,
            fixed_version=fixed,
            fix_state=fix_state,
        ),
    )


def test_inside_affected_range_is_vulnerable():
    r = make("5.6.0-2.el9", affected="< 5.6.2", fixed="5.6.2")
    assert r.is_vulnerable is Ternary.TRUE
    assert r.update_available is Ternary.TRUE
    assert r.version_gap is VersionGap.PATCH


def test_already_patched_is_not_vulnerable():
    r = make("5.6.2-1.el9", affected="< 5.6.2", fixed="5.6.2")
    assert r.is_vulnerable is Ternary.FALSE
    assert r.update_available is Ternary.FALSE


def test_scanner_disagreement_is_surfaced_not_hidden():
    """스캐너가 취약이라 했는데 버전 비교는 아니라고 하면 사람에게 알린다."""
    r = make("9.9.9", affected="< 5.6.2", fixed="5.6.2")
    assert r.is_vulnerable is Ternary.FALSE
    assert "확인 필요" in r.reason


def test_uncomparable_version_yields_unknown_not_false():
    r = make("git-abc123", ecosystem="npm", affected="< 2.0.0", fixed="2.0.0")
    assert r.is_vulnerable is Ternary.UNKNOWN
    assert r.update_available is Ternary.UNKNOWN
    assert r.version_gap is VersionGap.UNKNOWN
    assert "해석할 수 없음" in r.reason


def test_no_fix_available_means_no_update_target():
    r = make("1.2.11-40.el9", affected="*", fix_state=FixState.WONT_FIX)
    assert r.is_vulnerable is Ternary.TRUE
    assert r.update_available is Ternary.FALSE
    assert r.fix_state is FixState.WONT_FIX
    assert "수정 버전이 없어" in r.reason


def test_falls_back_to_fixed_version_when_no_range():
    r = make("1.0.0", ecosystem="npm", fixed="2.0.0")
    assert r.is_vulnerable is Ternary.TRUE
    assert r.version_gap is VersionGap.MAJOR


def test_no_range_and_no_fix_is_unknown():
    r = make("1.0.0", ecosystem="npm")
    assert r.is_vulnerable is Ternary.UNKNOWN
    assert "영향 버전범위도 수정 버전도 없음" in r.reason


def test_comparator_falls_back_to_installed_type():
    r = analyze(
        InstalledPackage(name="p", version="2.31.0", type="python"),
        AdvisoryPackage(
            advisory_package="p",
            advisory_ecosystem="",          # advisory가 생태계를 말해 주지 않았다
            affected_version_range="<2.32.0",
            fixed_version="2.32.0",
        ),
    )
    assert r.comparator == "pep440"
