"""FixAnalysis — Grype 판정을 옮기기만 한다.

**가장 중요한 계약: 우리 코드가 Grype 의 판정을 뒤집지 않는다.**

이 모듈은 한때 설치 버전과 advisory 버전범위를 우리 비교자로 다시 계산해
`is_vulnerable` 을 독립 산출했다. 그 설계에서는 우리 비교자에 흠이 하나만 있어도
Grype 가 취약하다고 탐지한 항목이 화면에 "취약 아니오"로 떴다 — 우리 버그 때문에
Grype 결과가 틀려 보이는 것이다.

이 도구는 Grype 를 신뢰하기로 선택했다. Grype 가 틀리면 그것은 Grype 의 오류이고
감수한다. 우리 코드 때문에 결과가 달라지는 것은 감수 대상이 아니다.

아래 테스트들은 그 경계를 고정한다.
"""

from core.fixanalysis import analyze
from core.models import AdvisoryPackage, FixState, InstalledPackage, Ternary, VersionGap


def make(installed_version, *, ecosystem="rpm", affected="", fixed="",
         fix_state=FixState.UNKNOWN, detected=True):
    return analyze(
        InstalledPackage(name="pkg", version=installed_version, type=ecosystem),
        AdvisoryPackage(
            advisory_package="pkg",
            advisory_ecosystem=ecosystem,
            affected_version_range=affected,
            fixed_version=fixed,
            fix_state=fix_state,
        ),
        detected_by_scanner=detected,
    )


class TestVerdictComesFromGrype:
    def test_detection_means_vulnerable(self):
        """Grype 가 매치를 만들었다는 사실이 곧 판정이다."""
        assert make("5.6.0-2.el9", affected="< 5.6.2", fixed="5.6.2").is_vulnerable is Ternary.TRUE

    def test_version_that_looks_patched_does_not_override_grype(self):
        """설치 버전이 수정 버전보다 높아 보여도 판정을 뒤집지 않는다.

        예전 구현은 여기서 `false` 를 냈다. 하지만 Grype 가 매치를 만들어 냈다면
        Grype 는 epoch·배포판 백포트·소스 패키지 관계까지 보고 그렇게 판정한
        것이다. 우리 비교자가 그보다 많이 알지 못한다.
        """
        assert make("9.9.9", affected="< 5.6.2", fixed="5.6.2").is_vulnerable is Ternary.TRUE

    def test_uncomparable_version_does_not_weaken_the_verdict(self):
        """버전 문자열을 못 읽어도 Grype 판정은 그대로다.

        예전 구현은 `unknown` 으로 떨어뜨렸다 — Grype 는 확신했는데 우리가
        확신을 깎아내린 것이다.
        """
        result = make("git-abc123", ecosystem="npm", affected="< 2.0.0", fixed="2.0.0")
        assert result.is_vulnerable is Ternary.TRUE
        assert result.version_gap is VersionGap.UNKNOWN      # 참고값만 미상

    def test_no_advisory_range_still_vulnerable(self):
        """advisory 에 버전범위가 없어도 Grype 가 탐지했으면 취약이다."""
        assert make("1.0.0", ecosystem="npm").is_vulnerable is Ternary.TRUE

    def test_undetected_is_unknown_not_false(self):
        """Grype 판정이 없는 경우에만 미확인이다. '안전하다'가 아니다."""
        assert make("1.0.0", detected=False).is_vulnerable is Ternary.UNKNOWN


class TestFixStateComesFromGrype:
    def test_fixed_state_means_update_available(self):
        result = make("5.6.0", ecosystem="npm", fixed="5.6.2",
                      fix_state=FixState.FIXED_AVAILABLE)
        assert result.update_available is Ternary.TRUE
        assert result.fix_state is FixState.FIXED_AVAILABLE

    def test_wont_fix_has_no_update_target(self):
        result = make("1.2.11-40.el9", fix_state=FixState.WONT_FIX)
        assert result.update_available is Ternary.FALSE
        assert result.fix_state is FixState.WONT_FIX
        assert "수정하지 않기로" in result.reason

    def test_not_fixed_has_no_update_target(self):
        result = make("1.2.11-40.el9", fix_state=FixState.NOT_FIXED)
        assert result.update_available is Ternary.FALSE
        assert "공개되지 않았습니다" in result.reason

    def test_unknown_state_stays_unknown(self):
        """Grype 도 모르는 것을 우리가 false 로 채우지 않는다."""
        result = make("1.0.0", ecosystem="npm")
        assert result.update_available is Ternary.UNKNOWN
        assert result.fix_state is FixState.UNKNOWN

    def test_fixed_version_without_state_is_treated_as_fixed(self):
        """Grype 가 state 를 비우고 수정 버전만 주는 경우가 있다."""
        result = make("1.0.0", ecosystem="npm", fixed="2.0.0")
        assert result.fix_state is FixState.FIXED_AVAILABLE
        assert result.update_available is Ternary.TRUE


class TestVersionGapIsDisplayOnly:
    def test_gap_is_computed_when_possible(self):
        assert make("5.6.0-2.el9", fixed="5.6.2").version_gap is VersionGap.PATCH
        assert make("1.0.0", ecosystem="npm", fixed="2.0.0").version_gap is VersionGap.MAJOR

    def test_gap_failure_never_touches_the_verdict(self):
        """격차를 못 구해도 판정·업데이트 가능 여부는 멀쩡해야 한다."""
        result = make("git-abc123", ecosystem="npm", fixed="2.0.0",
                      fix_state=FixState.FIXED_AVAILABLE)
        assert result.version_gap is VersionGap.UNKNOWN
        assert result.is_vulnerable is Ternary.TRUE
        assert result.update_available is Ternary.TRUE

    def test_no_fixed_version_means_no_gap(self):
        assert make("1.0.0", ecosystem="npm").version_gap is VersionGap.UNKNOWN


class TestComparatorSelection:
    def test_prefers_advisory_ecosystem(self):
        assert make("1.0.0", ecosystem="npm", fixed="2.0.0").comparator == "semver"

    def test_falls_back_to_installed_type(self):
        result = analyze(
            InstalledPackage(name="p", version="2.31.0", type="python"),
            AdvisoryPackage(
                advisory_package="p",
                advisory_ecosystem="",          # advisory 가 생태계를 말해 주지 않았다
                affected_version_range="<2.32.0",
                fixed_version="2.32.0",
            ),
        )
        assert result.comparator == "pep440"


class TestReasonIsNotDoubt:
    def test_reason_never_questions_the_verdict(self):
        """사유는 상태 설명이지, 판정을 의심하는 자리가 아니다.

        예전에는 "스캐너는 취약으로 탐지했으나 버전 비교상으로는 영향 범위 밖 —
        확인 필요" 같은 문장을 남겼다. 그 문장이 화면에 뜨면 읽는 사람은 Grype 를
        의심하게 되는데, 정작 틀린 쪽은 우리 비교자였다.
        """
        for result in (
            make("9.9.9", affected="< 5.6.2", fixed="5.6.2"),
            make("git-abc123", ecosystem="npm", affected="< 2.0.0", fixed="2.0.0"),
        ):
            assert "확인 필요" not in result.reason
            assert "비교할 수 없" not in result.reason
            assert "해석할 수 없" not in result.reason
