"""Grype 출력 정규화 테스트.

여기서 지키려는 계약은 두 가지다:
  1. 로컬 정보와 공개 정보가 올바른 계층으로 갈라져 담긴다.
  2. Grype의 표현상 함정(RHSA 대표 ID, epoch 누락, "none" 제약)에 넘어가지 않는다.
"""

import json
from pathlib import Path

import pytest

from core.models import FixState, Severity, Ternary
from core.normalize import normalize_grype_report, normalize_match

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


def test_detection_records_matcher_and_namespace(result):
    """[로컬 분석 정보]에 "왜 이 패키지가 걸렸는가"를 남긴다."""
    finding = by_package(result, "xz")
    assert finding.detection.matcher == "rpm-matcher"
    assert finding.detection.match_type == "exact-direct-match"
    assert finding.detection.namespace == "rocky:distro:rocky:9"
    assert finding.detection.search_criteria["package"]["name"] == "xz"


def test_empty_report_is_handled():
    result = normalize_grype_report({"matches": []}, scan_id="empty")
    assert result.findings == ()


class TestGrypeSuppliedIntel:
    """EPSS·KEV 는 Grype 가 준다.

    판정의 근간(CVSS·수정 상태)과 **같은 출처**에서 오므로 서로 어긋날 일이 없고,
    네트워크 없이도 늘 있다. 예전에는 FIRST·CISA 에서 따로 받아왔는데, 그러면
    스캔 시점과 스냅샷 시점이 갈라지고 폐쇄망에서는 아예 비었다.
    """

    @staticmethod
    def _match(**vuln):
        base = {
            "id": "CVE-2024-3094",
            "severity": "Critical",
            "fix": {"versions": ["5.6.2"], "state": "fixed"},
        }
        base.update(vuln)
        return {
            "artifact": {"name": "xz", "version": "5.6.0-2.el9", "type": "rpm"},
            "vulnerability": base,
        }

    def test_epss_is_read_from_grype(self):
        finding = normalize_match(self._match(
            epss=[{"cve": "CVE-2024-3094", "epss": 0.9134, "percentile": 0.9991, "date": "2026-08-20"}],
        ))
        assert finding.intel.epss == 0.9134
        assert finding.intel.epss_snapshot_date == "2026-08-20"

    def test_kev_listing_is_read_from_grype(self):
        finding = normalize_match(self._match(
            knownExploited=[{
                "cve": "CVE-2024-3094", "dateAdded": "2024-03-29",
                "knownRansomwareCampaignUse": "Known",
            }],
        ))
        assert finding.intel.kev is Ternary.TRUE
        assert finding.intel.kev_date_added == "2024-03-29"
        assert finding.intel.kev_ransomware_use == "Known"

    def test_empty_kev_list_means_looked_up_and_absent(self):
        """빈 목록은 Grype 가 조회했고 없었다는 뜻이다 — 그때만 '아니오'다."""
        finding = normalize_match(self._match(knownExploited=[]))
        assert finding.intel.kev is Ternary.FALSE

    def test_missing_kev_key_stays_unknown(self):
        """키 자체가 없으면 미확인이다.

        `false` 로 단정하면, KEV 를 담지 않는 DB 구성에서 실제로 악용 중인
        취약점이 화면에서 조용한 항목이 된다.
        """
        finding = normalize_match(self._match())
        assert finding.intel.kev is Ternary.UNKNOWN
        assert finding.intel.epss is None

    def test_epss_is_read_from_related_when_primary_lacks_it(self):
        """RHSA 가 primary 이고 CVE 가 related 에 있을 때도 값을 놓치지 않는다."""
        match = {
            "artifact": {"name": "openssl", "version": "1:3.0.7-24.el9", "type": "rpm"},
            "vulnerability": {"id": "RHSA-2024:2064", "severity": "Important",
                              "fix": {"versions": [], "state": "unknown"}},
            "relatedVulnerabilities": [{
                "id": "CVE-2024-2511", "severity": "Low",
                "epss": [{"cve": "CVE-2024-2511", "epss": 0.0043, "date": "2026-08-20"}],
                "knownExploited": [],
            }],
        }
        finding = normalize_match(match)
        assert finding.intel.cve == "CVE-2024-2511"
        assert finding.intel.epss == 0.0043
        assert finding.intel.kev is Ternary.FALSE

    def test_malformed_epss_entry_is_ignored_not_crashed(self):
        finding = normalize_match(self._match(epss=["nope", {"epss": None}, {}]))
        assert finding.intel.epss is None
