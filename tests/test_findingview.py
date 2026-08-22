"""정렬·필터·페이징.

가장 중요한 규칙 하나: **미확인 값은 정렬 방향과 무관하게 항상 뒤로 간다.**

CVSS나 EPSS가 없는 것은 "낮다"가 아니라 "모른다"이다. 내림차순에서 뒤로 가는
것은 자연스럽지만, 오름차순에서 맨 앞에 세우면 "가장 안전한 것"처럼 읽힌다.
그 오해는 실제로 조치를 누락시킨다.
"""

import pytest

from core import findingview
from core.models import (
    AdvisoryPackage, Finding, FixAnalysis, FixState, InstalledPackage, Priority,
    RuleVerdict, Severity, Ternary, VulnIntel,
)


def make(
    cve="CVE-2024-0001", package="pkg", version="1.0", cvss=None, epss=None,
    priority=Priority.P2, ptype="rpm", fixed="", flags=(), kev=Ternary.UNKNOWN,
    exploit=Ternary.UNKNOWN, vulnerable=Ternary.TRUE, update=Ternary.UNKNOWN,
):
    return Finding(
        installed=InstalledPackage(name=package, version=version, type=ptype),
        advisory=AdvisoryPackage(advisory_package=package, fixed_version=fixed),
        intel=VulnIntel(
            cve=cve, cvss_score=cvss, epss=epss, severity=Severity.UNKNOWN,
            kev=kev, exploit_available=exploit,
        ),
        fix=FixAnalysis(
            installed_version=version, fixed_version=fixed,
            is_vulnerable=vulnerable, update_available=update,
            fix_state=FixState.FIXED_AVAILABLE if fixed else FixState.UNKNOWN,
        ),
        verdict=RuleVerdict(priority=priority, flags=tuple(flags)),
    )


class TestUnknownAlwaysLast:
    @pytest.mark.parametrize("order", ["asc", "desc"])
    @pytest.mark.parametrize("field", ["cvss", "epss"])
    def test_missing_values_sort_last_in_both_directions(self, field, order):
        findings = [
            make(cve="CVE-1", **{field: 9.8 if field == "cvss" else 0.9}),
            make(cve="CVE-2"),                                   # 미확인
            make(cve="CVE-3", **{field: 1.0 if field == "cvss" else 0.1}),
            make(cve="CVE-4"),                                   # 미확인
        ]
        page = findingview.apply(findings, sort=field, order=order, limit=10)
        cves = [f.intel.cve for f in page.findings]
        assert cves[-2:] == ["CVE-2", "CVE-4"], (
            f"{order} 정렬에서 미확인이 뒤로 가지 않았다: {cves}"
        )

    def test_known_values_still_order_correctly(self):
        findings = [make(cve="CVE-1", cvss=5.0), make(cve="CVE-2", cvss=9.8),
                    make(cve="CVE-3"), make(cve="CVE-4", cvss=1.0)]
        desc = [f.intel.cve for f in
                findingview.apply(findings, sort="cvss", order="desc", limit=10).findings]
        assert desc == ["CVE-2", "CVE-1", "CVE-4", "CVE-3"]

        asc = [f.intel.cve for f in
               findingview.apply(findings, sort="cvss", order="asc", limit=10).findings]
        assert asc == ["CVE-4", "CVE-1", "CVE-2", "CVE-3"]

    def test_text_field_descending_keeps_unknown_last(self):
        """문자열 역순에서도 미확인이 앞으로 튀어나오면 안 된다.

        `reverse=True` 로 구현했다면 미확인을 뒤로 미는 칸까지 뒤집혀
        맨 앞에 왔을 것이다.
        """
        findings = [make(cve="CVE-1", fixed="1.0"), make(cve="CVE-2", fixed=""),
                    make(cve="CVE-3", fixed="9.0")]
        cves = [f.intel.cve for f in
                findingview.apply(findings, sort="fixed", order="desc", limit=10).findings]
        assert cves == ["CVE-3", "CVE-1", "CVE-2"]


class TestSorting:
    def test_priority_orders_by_urgency_not_alphabet(self):
        findings = [make(cve="CVE-3", priority=Priority.P3),
                    make(cve="CVE-0", priority=Priority.P0),
                    make(cve="CVE-2", priority=Priority.P2)]
        cves = [f.intel.cve for f in findingview.apply(findings, sort="priority").findings]
        assert cves == ["CVE-0", "CVE-2", "CVE-3"]

    def test_package_sort_is_case_insensitive(self):
        findings = [make(cve="CVE-1", package="Zlib"), make(cve="CVE-2", package="apr")]
        cves = [f.intel.cve for f in findingview.apply(findings, sort="package").findings]
        assert cves == ["CVE-2", "CVE-1"]

    def test_every_advertised_sort_key_works(self):
        findings = [make(cve=f"CVE-{i}", cvss=float(i), epss=i / 10) for i in range(5)]
        for key in findingview.SORT_KEYS:
            page = findingview.apply(findings, sort=key, limit=10)
            assert len(page.findings) == 5, f"{key} 정렬에서 항목이 사라졌다"


class TestFilters:
    def test_priority_filter(self):
        findings = [make(cve="CVE-1", priority=Priority.P0),
                    make(cve="CVE-2", priority=Priority.P3)]
        page = findingview.apply(findings, priority="P0")
        assert [f.intel.cve for f in page.findings] == ["CVE-1"]
        assert page.total == 1
        assert page.scan_total == 2

    def test_package_type_filter(self):
        findings = [make(cve="CVE-1", ptype="rpm"), make(cve="CVE-2", ptype="npm")]
        page = findingview.apply(findings, package_type="npm")
        assert [f.intel.cve for f in page.findings] == ["CVE-2"]

    @pytest.mark.parametrize("status,kwargs,expected", [
        ("update", {"update": Ternary.TRUE}, True),
        ("nofix", {"flags": ("no_fix_available",)}, True),
        ("unknown", {"vulnerable": Ternary.UNKNOWN}, True),
        ("kev", {"kev": Ternary.TRUE}, True),
        ("exploit", {"exploit": Ternary.TRUE}, True),
    ])
    def test_status_filters(self, status, kwargs, expected):
        hit = make(cve="CVE-HIT", **kwargs)
        miss = make(cve="CVE-MISS")
        page = findingview.apply([hit, miss], status=status)
        assert ("CVE-HIT" in [f.intel.cve for f in page.findings]) is expected
        assert "CVE-MISS" not in [f.intel.cve for f in page.findings]

    def test_text_search_covers_cve_and_package(self):
        findings = [make(cve="CVE-2024-3094", package="xz"),
                    make(cve="CVE-2023-45853", package="zlib")]
        assert findingview.apply(findings, query="xz").total == 1
        assert findingview.apply(findings, query="45853").total == 1
        assert findingview.apply(findings, query="ZLIB").total == 1      # 대소문자 무시

    def test_filters_combine(self):
        findings = [
            make(cve="CVE-1", priority=Priority.P0, ptype="rpm", kev=Ternary.TRUE),
            make(cve="CVE-2", priority=Priority.P0, ptype="npm", kev=Ternary.TRUE),
            make(cve="CVE-3", priority=Priority.P3, ptype="rpm", kev=Ternary.TRUE),
        ]
        page = findingview.apply(findings, priority="P0", package_type="rpm", status="kev")
        assert [f.intel.cve for f in page.findings] == ["CVE-1"]


class TestPaging:
    def test_total_is_before_slicing(self):
        findings = [make(cve=f"CVE-{i}") for i in range(250)]
        page = findingview.apply(findings, offset=0, limit=100)
        assert len(page.findings) == 100
        assert page.total == 250
        assert page.has_more is True

    def test_last_page_reports_no_more(self):
        findings = [make(cve=f"CVE-{i}") for i in range(250)]
        page = findingview.apply(findings, offset=200, limit=100)
        assert len(page.findings) == 50
        assert page.has_more is False

    def test_offset_past_the_end_is_empty_not_an_error(self):
        page = findingview.apply([make()], offset=500, limit=100)
        assert page.findings == ()
        assert page.total == 1

    def test_limit_is_clamped(self):
        findings = [make(cve=f"CVE-{i}") for i in range(2000)]
        assert findingview.apply(findings, limit=99999).limit == 1000
        assert findingview.apply(findings, limit=0).limit == 1

    def test_paging_covers_every_finding_exactly_once(self):
        findings = [make(cve=f"CVE-{i:04}", cvss=float(i % 7)) for i in range(230)]
        seen = []
        offset = 0
        while True:
            page = findingview.apply(findings, sort="cvss", order="desc",
                                     offset=offset, limit=50)
            seen.extend(f.intel.cve for f in page.findings)
            if not page.has_more:
                break
            offset += page.limit
        assert len(seen) == 230
        assert len(set(seen)) == 230, "페이지가 겹치거나 빠졌다"


class TestPackageTypes:
    def test_lists_types_present_sorted(self):
        findings = [make(ptype="rpm"), make(ptype="npm"), make(ptype="rpm"), make(ptype="")]
        assert findingview.package_types(findings) == ["npm", "rpm"]
