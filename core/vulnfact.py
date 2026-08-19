"""이그레스 경계 — AI로 나가는 유일한 객체를 조립한다.

**거르기가 아니라 조립이다.** 원본에서 위험한 필드를 지우는 방식은 새 필드가
추가되는 순간 뚫린다. 여기서는 허용 필드만 명시적으로 새 객체에 옮겨 담는다.

이 모듈의 핵심 방어는 코드가 아니라 **함수 시그니처**다:

    def build_vuln_fact(advisory: AdvisoryPackage, intel: VulnIntel) -> dict

`InstalledPackage`(설치 버전·파일 경로), `FixAnalysis`(취약 여부 판정),
`RuleVerdict`(대응 우선순위), `Detection`(탐지 근거)은 인자로 들어오지도
않는다. 실수로 넣으려면 시그니처를 고쳐야 하고, 그러면 리뷰에서 보인다.

조립 결과는 core/sanitizer.py 가 policy/egress-policy.json 에 대고
다시 검증한다. 조립이 어긋났을 때를 대비한 2차 방어다.
"""

from __future__ import annotations

from typing import Any

from .models import AdvisoryPackage, Finding, VulnIntel

__all__ = ["build_vuln_fact", "build_from_finding", "build_batch"]

# exploit_sources에서 내보낼 소스 종류. 저장소가 채운 자유 텍스트(note)는
# 무엇이 들어 있을지 보장할 수 없으므로 식별자만 보낸다.
_ALLOWED_EXPLOIT_SOURCES = {"exploit_db", "metasploit", "github_poc", "nuclei"}


def build_vuln_fact(advisory: AdvisoryPackage, intel: VulnIntel) -> dict[str, Any]:
    """공개 계층 두 개에서만 VulnFact를 조립한다.

    로컬 계층은 인자에 없다. 이것이 이 파일의 요점이다.
    """
    return {
        # --- 취약점 식별 (공개) ---
        "cve": intel.cve,
        "cvss_score": intel.cvss_score,
        "cvss_vector": intel.cvss_vector,
        "cvss_version": intel.cvss_version,
        "severity": intel.severity.value,
        "cwe": list(intel.cwe),
        "published": intel.published,

        # --- 악용 가능성 (공개) ---
        "epss": intel.epss,
        "epss_percentile": intel.epss_percentile,
        "epss_snapshot_date": intel.epss_snapshot_date,
        "kev": intel.kev.value,
        "kev_date_added": intel.kev_date_added,
        "kev_ransomware_use": intel.kev_ransomware_use,
        "exploit_available": intel.exploit_available.value,
        "exploit_maturity": intel.exploit_maturity.value,
        "exploit_sources": [
            {"source": source.source, "ref": source.ref}
            for source in intel.exploit_sources
            if source.source in _ALLOWED_EXPLOIT_SOURCES
        ],

        # --- advisory가 지목한 대상 (공개) ---
        # 아래 세 값은 전부 advisory가 공표한 것이지 우리 자산의 사실이 아니다.
        "advisory_package": advisory.advisory_package,
        "advisory_ecosystem": advisory.advisory_ecosystem,
        "affected_version_range": advisory.affected_version_range,
        "fixed_version": advisory.fixed_version,
        "os_family": advisory.os_family,
    }


def build_from_finding(finding: Finding) -> dict[str, Any]:
    """Finding에서 공개 계층만 꺼내 넘긴다.

    본문이 한 줄인 이유가 있다 — 로컬 계층을 참조하지 않는다는 것을 눈으로
    확인할 수 있어야 하기 때문이다. 여기에 조건문이 붙기 시작하면 그 자체가
    설계가 무너지고 있다는 신호다.
    """
    return build_vuln_fact(finding.advisory, finding.intel)


def build_batch(findings: tuple[Finding, ...] | list[Finding]) -> list[dict[str, Any]]:
    """여러 Finding을 VulnFact 목록으로 옮긴다.

    같은 CVE·패키지 조합이 여러 자산에서 나와도 **한 번만** 내보낸다.
    중복 건수는 곧 '우리 환경에 몇 대나 있는가'라는 내부 정보이기 때문이다.
    """
    seen: set[tuple[str, str, str]] = set()
    facts: list[dict[str, Any]] = []
    for finding in findings:
        key = (
            finding.intel.cve,
            finding.advisory.advisory_package,
            finding.advisory.advisory_ecosystem,
        )
        if key in seen:
            continue
        seen.add(key)
        facts.append(build_from_finding(finding))
    return facts
