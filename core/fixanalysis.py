"""[로컬 전용] 설치 버전 ↔ Fixed Version 비교 판정.

여기서 나오는 값은 **우리 환경에 대한 사실**이므로 AI에 전달하지 않는다.
AI는 advisory의 버전 범위만 알 뿐, 우리가 그 범위 안에 있는지는 모른다.

Grype가 매치를 만들어냈다는 사실 자체가 이미 "취약하다"는 판정이지만,
여기서는 그것을 그대로 믿지 않고 **독립적으로 다시 계산한다.** 두 판정이
엇갈리면 그 사실을 `reason`에 남긴다 — 조용히 한쪽을 고르는 것보다
사람이 알아보는 편이 낫다.
"""

from __future__ import annotations

from .models import (
    AdvisoryPackage,
    FixAnalysis,
    FixState,
    InstalledPackage,
    Ternary,
    VersionGap,
)
from .versioning import compare, comparator_for, satisfies, version_gap


def _pick_comparator(installed: InstalledPackage, advisory: AdvisoryPackage) -> str:
    """advisory 생태계를 우선하되, 비어 있으면 설치 패키지 타입으로 정한다."""
    for candidate in (advisory.advisory_ecosystem, installed.type):
        name = comparator_for(candidate)
        if name != "generic":
            return name
    return "generic"


def analyze(
    installed: InstalledPackage,
    advisory: AdvisoryPackage,
    *,
    detected_by_scanner: bool = True,
) -> FixAnalysis:
    """설치 버전과 advisory를 비교해 로컬 판정을 만든다.

    detected_by_scanner: Grype 등 스캐너가 이 조합을 취약하다고 판정했는지.
        독립 계산 결과와 엇갈릴 때 reason에 남기기 위해 받는다.
    """
    comparator = _pick_comparator(installed, advisory)
    version = installed.version
    fixed = advisory.fixed_version
    reasons: list[str] = []

    # --- 취약 여부 -------------------------------------------------------
    vulnerable: bool | None = None
    if advisory.affected_version_range:
        vulnerable = satisfies(version, advisory.affected_version_range, comparator)
        if vulnerable is None:
            reasons.append(
                f"영향 버전범위 '{advisory.affected_version_range}'를 "
                f"{comparator} 규칙으로 해석할 수 없음"
            )
    elif fixed:
        rc = compare(version, fixed, comparator)
        if rc is None:
            reasons.append(
                f"설치 버전 '{version}'과 수정 버전 '{fixed}'를 "
                f"{comparator} 규칙으로 비교할 수 없음"
            )
        else:
            vulnerable = rc < 0
    else:
        reasons.append("advisory에 영향 버전범위도 수정 버전도 없음")

    # 스캐너 판정과 독립 계산이 엇갈리면 숨기지 않고 드러낸다.
    if vulnerable is False and detected_by_scanner:
        reasons.append(
            "스캐너는 취약으로 탐지했으나 버전 비교상으로는 영향 범위 밖 — 확인 필요"
        )

    # --- 업데이트 가능 여부 ----------------------------------------------
    if not fixed:
        update_available: bool | None = False
        reasons.append("공개된 수정 버전이 없어 업데이트 대상이 존재하지 않음")
    else:
        rc = compare(version, fixed, comparator)
        if rc is None:
            update_available = None
        else:
            update_available = rc < 0

    # --- 수정 상태 --------------------------------------------------------
    if advisory.fix_state is not FixState.UNKNOWN:
        fix_state = advisory.fix_state
    elif fixed:
        fix_state = FixState.FIXED_AVAILABLE
    else:
        fix_state = FixState.UNKNOWN

    # --- 버전 격차 --------------------------------------------------------
    gap = VersionGap.UNKNOWN
    if fixed:
        try:
            gap = VersionGap(version_gap(version, fixed, comparator))
        except ValueError:
            gap = VersionGap.UNKNOWN

    return FixAnalysis(
        installed_version=version,
        fixed_version=fixed,
        comparator=comparator,
        is_vulnerable=Ternary.of(vulnerable),
        update_available=Ternary.of(update_available),
        fix_state=fix_state,
        version_gap=gap,
        reason="; ".join(reasons),
    )
