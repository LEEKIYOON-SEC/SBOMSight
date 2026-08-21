"""버전 비교자 테스트.

벡터는 tests/fixtures/version-vectors.json 에 있다.

rpm 케이스는 rpm 프로젝트의 rpmvercmp 테스트 스위트에서 가져왔다. 우리 구현이
rpm과 다르게 동작하면 FixAnalysis가 틀리고, 그것은 곧 패치 누락이나 헛된 패치
작업으로 이어진다.
"""

import json
from pathlib import Path

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

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "version-vectors.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("a,b,expected", VECTORS["compare"]["rpm"], ids=lambda v: str(v))
def test_rpmvercmp_matches_rpm_upstream(a, b, expected):
    assert rpm_compare(a, b) == expected, f"rpm_compare({a!r}, {b!r})"


@pytest.mark.parametrize("a,b,expected", VECTORS["compare"]["deb"], ids=lambda v: str(v))
def test_deb_compare(a, b, expected):
    assert deb_compare(a, b) == expected


@pytest.mark.parametrize("a,b,expected", VECTORS["compare"]["semver"], ids=lambda v: str(v))
def test_semver_compare(a, b, expected):
    assert semver_compare(a, b) == expected


@pytest.mark.parametrize("a,b,expected", VECTORS["compare"]["pep440"], ids=lambda v: str(v))
def test_pep440_compare(a, b, expected):
    assert pep440_compare(a, b) == expected


@pytest.mark.parametrize("comparator,a,b", VECTORS["uncomparable"], ids=lambda v: str(v))
def test_uncomparable_versions_return_none_not_false(comparator, a, b):
    """이것이 이 모듈의 핵심 계약이다. 비교할 수 없을 때 "취약하지 않다"고
    답해 버리면 패치 누락이 된다."""
    assert compare(a, b, comparator) is None


@pytest.mark.parametrize("comparator,version,constraint,expected", VECTORS["satisfies"],
                         ids=lambda v: str(v))
def test_satisfies(comparator, version, constraint, expected):
    assert satisfies(version, constraint, comparator) is expected


@pytest.mark.parametrize("comparator,installed,fixed,expected", VECTORS["version_gap"],
                         ids=lambda v: str(v))
def test_version_gap(comparator, installed, fixed, expected):
    assert version_gap(installed, fixed, comparator) == expected


@pytest.mark.parametrize("ecosystem,expected", VECTORS["comparator_for"], ids=lambda v: str(v))
def test_comparator_for_maps_ecosystems(ecosystem, expected):
    assert comparator_for(ecosystem) == expected


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


def test_generic_is_last_resort_and_still_orders():
    assert generic_compare("1.2.3", "1.2.4") == -1
    assert generic_compare("abc", "abd") == -1
