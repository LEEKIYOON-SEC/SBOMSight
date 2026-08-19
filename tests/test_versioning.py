"""버전 비교자 테스트.

rpm 케이스는 rpm 프로젝트의 rpmvercmp 테스트 스위트(tests/rpmvercmp.at)에서
가져온 벡터다. 우리 구현이 rpm과 다르게 동작하면 FixAnalysis가 틀리고,
그것은 곧 패치 누락이나 헛된 패치 작업으로 이어진다.
"""

import pytest

from core.versioning import (
    compare,
    comparator_for,
    deb_compare,
    generic_compare,
    pep440_compare,
    rpm_compare,
    satisfies,
    semver_compare,
    version_gap,
)


RPM_VECTORS = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1),
    ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0),
    ("5.5p1", "5.5p10", -1),
    ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1),
    ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0),
    ("xyz10", "xyz10.1", -1),
    ("xyz.4", "xyz.4", 0),
    ("xyz.4", "8", -1),
    ("8", "xyz.4", 1),
    ("xyz.4", "2", -1),
    ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1),
    ("5.6p1", "5.5p2", 1),
    ("6.0.rc1", "6.0", 1),
    ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1),
    ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0),
    ("1.0a", "1.0aa", -1),
    ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0),
    ("10.0001", "10.1", 0),
    ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1),
    ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1),
    ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0),
    ("20101121", "20101122", -1),
    ("20101122", "20101121", 1),
    ("2_0", "2_0", 0),
    ("2.0", "2_0", 0),
    ("2_0", "2.0", 0),
    # 틸드 — 무엇보다도 앞선다
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    # 캐럿 — 문자열 끝보다는 뒤, 다른 문자보다는 앞
    ("1.0^", "1.0^", 0),
    ("1.0^", "1.0", 1),
    ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0),
    ("1.0^git1", "1.0", 1),
    ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1),
    ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0),
    ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
    # 실사용 형태
    ("1b.fc17", "1b.fc17", 0),
    ("1b.fc17", "1.fc17", -1),
    ("1.fc17", "1b.fc17", 1),
    ("1g.fc17", "1g.fc17", 0),
    # "1b"는 "1"보다 낮고 "1g"는 "1"보다 높다. 두 번째 세그먼트가 각각
    # "b" vs "fc", "g" vs "fc" 로 비교되기 때문이다 (b < fc < g).
    ("1g.fc17", "1.fc17", 1),
    ("1.fc17", "1g.fc17", -1),
]


@pytest.mark.parametrize("a,b,expected", RPM_VECTORS)
def test_rpmvercmp_matches_rpm_upstream(a, b, expected):
    assert rpm_compare(a, b) == expected, f"rpm_compare({a!r}, {b!r})"


def test_rpm_epoch_dominates_version():
    # epoch가 있는 쪽이 무조건 높다. epoch를 빠뜨리면 패치된 패키지를
    # 취약하다고 오판하게 된다.
    assert rpm_compare("1:3.2.2-6.el10", "3.2.2-6.el10") == 1
    assert rpm_compare("0:1.0", "1.0") == 0


def test_rpm_release_ignored_when_one_side_omits_it():
    # advisory가 "5.6.2"라고만 말했는데 설치본이 "5.6.2-1.el9"라고 해서
    # release로 갈라서면 안 된다.
    assert rpm_compare("5.6.2-1.el9", "5.6.2") == 0
    assert rpm_compare("5.6.2-1.el9", "5.6.2-2.el9") == -1


DEB_VECTORS = [
    ("1.0", "1.0", 0),
    ("1.0", "1.1", -1),
    ("1:1.0", "2.0", 1),
    ("1.0~beta1", "1.0", -1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-1", "1.0", 0),
    ("2.2.4-1", "2.2.4-1", 0),
    ("1.0~~", "1.0~", -1),
    ("1.0~", "1.0", -1),
]


@pytest.mark.parametrize("a,b,expected", DEB_VECTORS)
def test_deb_compare(a, b, expected):
    assert deb_compare(a, b) == expected


SEMVER_VECTORS = [
    ("1.0.0", "1.0.0", 0),
    ("1.0.0", "1.0.1", -1),
    ("1.2.0", "1.10.0", -1),
    ("1.0.0-rc1", "1.0.0", -1),
    ("1.0.0-alpha", "1.0.0-beta", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-1", "1.0.0-alpha", -1),
    ("1.0.0+build1", "1.0.0+build2", 0),
    ("v2.0.0", "2.0.0", 0),
    ("7.0.3", "7.0.5", -1),
]


@pytest.mark.parametrize("a,b,expected", SEMVER_VECTORS)
def test_semver_compare(a, b, expected):
    assert semver_compare(a, b) == expected


PEP440_VECTORS = [
    ("1.0", "1.0.0", 0),
    ("1.0", "1.1", -1),
    ("1.0a1", "1.0", -1),
    ("1.0rc1", "1.0", -1),
    ("1.0a1", "1.0b1", -1),
    ("1.0.dev1", "1.0a1", -1),
    ("1.0", "1.0.post1", -1),
    ("1!1.0", "2.0", 1),
    ("2.31.0", "2.32.0", -1),
    ("1.0+local", "1.0", 0),
]


@pytest.mark.parametrize("a,b,expected", PEP440_VECTORS)
def test_pep440_compare(a, b, expected):
    assert pep440_compare(a, b) == expected


def test_unparseable_versions_return_none_not_false():
    # 이것이 이 모듈의 핵심 계약이다. 비교할 수 없을 때 "취약하지 않다"고
    # 답해 버리면 패치 누락이 된다.
    assert semver_compare("git-abc123", "2.0.0") is None
    assert pep440_compare("not-a-version", "1.0") is None
    assert compare("", "1.0", "rpm") is None
    assert compare("1.0", "", "rpm") is None


def test_comparator_for_maps_ecosystems():
    assert comparator_for("rpm") == "rpm"
    assert comparator_for("Rocky") == "rpm"
    assert comparator_for("npm") == "semver"
    assert comparator_for("python") == "pep440"
    assert comparator_for("pypi") == "pep440"
    assert comparator_for("ubuntu") == "deb"
    assert comparator_for("") == "generic"
    assert comparator_for("무언가-모르는-것") == "generic"


class TestSatisfies:
    def test_simple_upper_bound(self):
        assert satisfies("5.6.0", "< 5.6.2", "rpm") is True
        assert satisfies("5.6.2", "< 5.6.2", "rpm") is False

    def test_and_group(self):
        assert satisfies("7.0.3", ">=7.0.0,<7.0.5", "semver") is True
        assert satisfies("6.9.0", ">=7.0.0,<7.0.5", "semver") is False

    def test_or_group(self):
        expr = "<1.2.3 || >=2.0.0,<2.1.0"
        assert satisfies("2.0.5", expr, "semver") is True
        assert satisfies("1.0.0", expr, "semver") is True
        assert satisfies("3.0.0", expr, "semver") is False

    def test_none_means_all_versions_affected(self):
        # Grype는 "제약 없음"을 "none"으로 쓴다. 버전 이름이 아니다.
        assert satisfies("1.2.11-40.el9", "none", "rpm") is True
        assert satisfies("1.2.11-40.el9", "*", "rpm") is True

    def test_unparseable_yields_none(self):
        assert satisfies("git-abc", "< 5.6.2", "semver") is None
        assert satisfies("1.0", "", "rpm") is None


def test_version_gap_reports_unknown_when_uncomparable():
    assert version_gap("git-abc123", "2.0.0", "semver") == "unknown"
    assert version_gap("5.6.2", "5.6.2", "rpm") == "none"
    assert version_gap("5.4.0", "5.6.2", "rpm") == "minor"
    assert version_gap("1.2.3", "2.0.0", "semver") == "major"


def test_generic_is_last_resort_and_still_orders():
    assert generic_compare("1.2.3", "1.2.4") == -1
    assert generic_compare("abc", "abd") == -1
