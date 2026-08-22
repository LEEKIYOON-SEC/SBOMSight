"""[로컬 전용] Grype 판정을 사람이 읽을 형태로 옮긴다.

**여기서 취약 여부를 판정하지 않는다.**

이 모듈은 한때 설치 버전과 advisory 버전범위를 우리 비교자로 다시 계산해
`is_vulnerable` 을 독립적으로 산출했다. "스캐너를 그대로 믿지 않는다"는 의도였지만
그 설계는 틀렸다. 우리 비교자에 흠이 하나라도 있으면 Grype 가 취약하다고 탐지한
항목이 화면에 "취약 아니오"로 뜬다 — 우리 버그 때문에 Grype 결과가 틀려 보인다.

이 도구는 **Grype 를 신뢰하기로 선택한 도구**다. Grype 가 틀리면 그건 Grype 의
오류이고 감수한다. 하지만 우리 코드 때문에 Grype 의 결과가 달라지는 일은 없어야
한다. 그래서 판정의 출처는 하나다:

    취약 여부      Grype 가 이 매치를 만들어 냈다  →  취약
    수정본 유무    Grype 의 fix.state 를 그대로 옮긴다
    수정 버전      Grype 의 fix.versions 를 그대로 옮긴다

버전 비교는 `version_gap` 하나에만 남는다. 그것은 "얼마나 밀렸는가"를 눈대중으로
보여 주는 참고값일 뿐, 어떤 판정에도 관여하지 않는다. 계산하지 못하면 조용히
`unknown` 이 되고, 그것으로 끝이다 — 판정을 흔들지 않는다.
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
from .versioning import comparator_for, version_gap

# Grype 의 fix.state 가 곧 "업데이트할 것이 있는가"에 대한 답이다.
#   fixed      수정 버전이 공개되어 있다
#   not-fixed  아직 수정되지 않았다
#   wont-fix   수정하지 않기로 했다
#   unknown    Grype 도 모른다  ← 0이나 false 로 뭉개지 않는다
_UPDATE_AVAILABLE = {
    FixState.FIXED_AVAILABLE: Ternary.TRUE,
    FixState.NOT_FIXED: Ternary.FALSE,
    FixState.WONT_FIX: Ternary.FALSE,
    FixState.UNKNOWN: Ternary.UNKNOWN,
}


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
    """Grype 의 판정을 FixAnalysis 로 옮긴다. 다시 계산하지 않는다.

    detected_by_scanner: Grype 가 이 조합에 대해 매치를 만들어 냈는가.
        Grype 결과에서 온 Finding 이라면 언제나 참이다 — 매치가 존재한다는
        사실 자체가 Grype 의 "취약하다"는 판정이기 때문이다.
    """
    comparator = _pick_comparator(installed, advisory)
    fixed = advisory.fixed_version

    # --- 취약 여부 — Grype 가 답한다 ---------------------------------------
    is_vulnerable = Ternary.TRUE if detected_by_scanner else Ternary.UNKNOWN

    # --- 수정 상태와 업데이트 가능 여부 — Grype 가 답한다 --------------------
    fix_state = advisory.fix_state
    if fix_state is FixState.UNKNOWN and fixed:
        # Grype 가 state 를 비워 두고 수정 버전만 준 경우가 있다.
        # 수정 버전이 있다는 것 자체가 fixed 라는 뜻이므로 그것만 받아들인다.
        fix_state = FixState.FIXED_AVAILABLE
    update_available = _UPDATE_AVAILABLE[fix_state]

    # --- 버전 격차 — 표시용 참고값. 판정에 관여하지 않는다 -------------------
    gap = VersionGap.UNKNOWN
    if fixed and installed.version:
        try:
            gap = VersionGap(version_gap(installed.version, fixed, comparator))
        except ValueError:
            gap = VersionGap.UNKNOWN

    return FixAnalysis(
        installed_version=installed.version,
        fixed_version=fixed,
        comparator=comparator,
        is_vulnerable=is_vulnerable,
        update_available=update_available,
        fix_state=fix_state,
        version_gap=gap,
        reason=_reason(fix_state, fixed),
    )


def _reason(fix_state: FixState, fixed: str) -> str:
    """왜 이런 상태인지 한 줄. 판정에 대한 의심을 적는 자리가 아니다."""
    if fix_state is FixState.WONT_FIX:
        return "공급자가 수정하지 않기로 한 항목입니다. 완화 방안을 검토하세요."
    if fix_state is FixState.NOT_FIXED:
        return "아직 수정 버전이 공개되지 않았습니다."
    if fix_state is FixState.UNKNOWN and not fixed:
        return "Grype 데이터에 수정 상태 정보가 없습니다."
    return ""
