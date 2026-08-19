"""Grype 출력 정규화 테스트.

여기서 지키려는 계약은 두 가지다:
  1. 로컬 정보와 공개 정보가 올바른 계층으로 갈라져 담긴다.
  2. Grype의 표현상 함정(RHSA 대표 ID, epoch 누락, "none" 제약)에 넘어가지 않는다.
"""

import json
from pathlib import Path

import pytest

from core.models import FixState, Severity, Ternary
from core.normalize import normalize_grype_report

FIXTURE = Path(__file__).parent / "fixtures" / "grype-sample.json"


@pytest.fixture(scope="module")
def result():
    return normalize_grype_report(
        json.loads(FIXTURE.read_text()),
        scan_id="test-scan",
        sbom_filename="sample.cdx.json",
        sbom_format="cyclonedx-json",
        component_count=1204,
    )


def by_package(result, name):
    return next(f for f in result.findings if f.installed.name == name)


def test_all_matches_normalized(result):
    assert len(result.findings) == 5
    assert result.metadata.grype_version == "0.79.0"
    assert result.metadata.grype_db_built == "2026-08-18T01:23:45Z"
    assert result.metadata.component_count == 1204


def test_layers_are_separated(result):
    """로컬 계층과 공개 계층이 각자의 객체에 담겼는가."""
    finding = by_package(result, "xz")
    # 로컬 전용 — 파일 경로는 대표적인 내부 정보다
    assert finding.installed.locations == ("/var/lib/rpm/rpmdb.sqlite",)
    assert finding.installed.version == "5.6.0-2.el9"
    # 공개 — advisory가 지목한 식별자와 공표한 버전
    assert finding.advisory.advisory_package == "xz"
    assert finding.advisory.fixed_version == "5.6.2"
    assert finding.advisory.affected_version_range == "< 5.6.2"
    # 공개 위협정보
    assert finding.intel.cve == "CVE-2024-3094"
    assert finding.intel.cvss_score == 10.0
    assert finding.intel.severity is Severity.CRITICAL


def test_distro_advisory_is_resolved_to_cve(result):
    """primary가 RHSA-…여도 대표 ID는 CVE가 되어야 한다."""
    finding = by_package(result, "openssl")
    assert finding.intel.cve == "CVE-2024-2511"
    assert "RHSA-2024:2064" in finding.intel.aliases
    # CVSS는 relatedVulnerabilities 쪽에만 있었다 — 병합되어야 한다.
    assert finding.intel.cvss_score == 5.3
    assert finding.intel.description.startswith("Some non-default TLS")


def test_ghsa_advisory_is_resolved_to_cve(result):
    finding = by_package(result, "cross-spawn")
    assert finding.intel.cve == "CVE-2024-21538"
    assert "GHSA-3xgq-45jj-v275" in finding.intel.aliases
    assert finding.intel.cvss_score == 7.5


def test_rpm_epoch_is_restored_on_installed_version(result):
    """Grype는 artifact.version에서 epoch를 빼고 제약식에는 붙여 준다.

    맞춰 주지 않으면 epoch 유무가 갈려 오판이 난다.
    """
    finding = by_package(result, "openssl")
    assert finding.installed.version == "1:3.0.7-24.el9"
    assert finding.advisory.affected_version_range == "< 1:3.0.7-27.el9_4"
    assert finding.fix.is_vulnerable is Ternary.TRUE


def test_grype_none_constraint_means_all_versions(result):
    """versionConstraint "none"은 버전 이름이 아니라 '제약 없음'이다."""
    finding = by_package(result, "zlib")
    assert finding.advisory.affected_version_range == "*"
    assert finding.fix.is_vulnerable is Ternary.TRUE
    # wont-fix라 업데이트 대상이 없다 — 완화 방안 검토가 필요한 유형이다.
    assert finding.fix.fix_state is FixState.WONT_FIX
    assert finding.fix.update_available is Ternary.FALSE


def test_constraint_format_suffix_is_stripped(result):
    for finding in result.findings:
        assert "(rpm)" not in finding.advisory.affected_version_range
        assert "(python)" not in finding.advisory.affected_version_range


def test_comparator_chosen_per_ecosystem(result):
    assert by_package(result, "xz").fix.comparator == "rpm"
    assert by_package(result, "cross-spawn").fix.comparator == "semver"
    assert by_package(result, "requests").fix.comparator == "pep440"


def test_os_family_from_distro_id_like(result):
    assert by_package(result, "xz").advisory.os_family == "rhel"


def test_references_are_merged_from_both_sources(result):
    finding = by_package(result, "openssl")
    assert "https://access.redhat.com/errata/RHSA-2024:2064" in finding.intel.references
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-2511" in finding.intel.references


def test_empty_report_is_handled():
    result = normalize_grype_report({"matches": []}, scan_id="empty")
    assert result.findings == ()
