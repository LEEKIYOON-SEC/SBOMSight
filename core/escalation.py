"""연계 상승(escalation) 후보 고르기.

**AI 가 하는 일이 아니다.** 여기서 하는 것은 "어떤 취약점들을 나란히 놓고
물어볼 것인가"를 CVSS 벡터만으로 정하는 일이고, 그 판단은 결정론적이다.
AI 는 고른 것들 사이의 연쇄 논리를 서술할 뿐이다.

## 왜 이 모듈이 필요한가

연계 분석을 **패키지 안에서만** 돌리고 있었다. 그런데 한 패키지 안의 CVE
여섯 건은 같은 라이브러리의 서로 무관한 버그이고, 조치도 버전 하나 올리는
것으로 같다 — 엮을 것이 없다. 실제로 등급이 뛰는 조합은 **패키지를 가로지른다**:

    openssl 의 정보 노출(PR:N, C:H)  →  sudo 의 권한 상승(PR:L, C:H/I:H/A:H)

앞의 것이 뒤의 것이 요구하는 자격(`PR:L`)을 만들어 준다. 둘 다 따로 보면
중간 등급이지만 이어지면 인증 없는 원격 장악이 된다. 그것이 담당자가 기대한
"저위험이 고위험으로 에스컬레이드" 다.

## 어떻게 고르는가

CVSS 벡터에서 두 역할을 읽는다.

- **발판(foothold)** — `PR:N`. 자격 없이 성립하고, 성공하면 무언가를 얻는다
  (정보 노출 `C:H`, 무결성 훼손 `I:H`, 또는 범위 변경 `S:C`).
- **상승(escalation)** — `PR:L`/`PR:H`. 자격을 요구하지만 성공하면 크게
  번진다(`C:H`·`I:H`·`A:H` 중 하나 이상).

발판이 상승의 전제를 채워 주는 모양이라야 연쇄가 성립한다. 그래서 두 갈래를
따로 뽑아 함께 보낸다 — 한 갈래만 보내면 모델이 엮을 상대가 없다.

## 전송량

48,923건을 다 보낼 수는 없다. 갈래마다 상한을 두고, **실제 악용 확인(KEV) →
악용 예측(EPSS) → CVSS** 순으로 골라 담는다. 뽑는 기준이 결정론적이므로 같은
스캔에서는 같은 후보가 나오고, 무엇이 왜 뽑혔는지 화면에 그대로 적을 수 있다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import cvss

#: 갈래별 기본 상한. 40건이면 프롬프트가 대략 12~15K 토큰이고, 분당 토큰
#: 한도 안에서 한 번에 처리된다. 넘기면 첫 요청부터 실패한다.
DEFAULT_LIMIT = 20

FOOTHOLD = "foothold"
ESCALATION = "escalation"

ROLE_LABEL = {
    FOOTHOLD: "발판 — 자격 없이 성립",
    ESCALATION: "상승 — 자격을 요구하지만 크게 번짐",
}


@dataclass(frozen=True)
class Candidate:
    """후보 하나와 **왜 뽑혔는지**.

    이유를 함께 들고 다니는 이유는 화면에 적기 위해서다. "AI 가 골랐다"가
    아니라 "PR:N 이고 C:H 라서 발판 후보로 골랐다"라고 말할 수 있어야 한다.
    """

    cve: str
    role: str
    reason: str
    score: tuple


def _impact(metrics: dict[str, str]) -> tuple[str, str, str]:
    """v3.x 와 v4.0 의 영향 메트릭 이름이 다르다. 한 이름으로 맞춘다."""
    return (
        metrics.get("C") or metrics.get("VC") or "",
        metrics.get("I") or metrics.get("VI") or "",
        metrics.get("A") or metrics.get("VA") or "",
    )


def classify(vector: str) -> tuple[str, str] | None:
    """벡터 하나를 (역할, 이유)로 옮긴다. 어느 쪽도 아니면 None.

    벡터가 없으면 아무 역할도 주지 않는다 — 근거 없이 연쇄 논리에 넣으면
    모델이 지어내는 자리가 된다. 프롬프트에서도 같은 제약을 건다.
    """
    metrics = cvss.parse_vector(vector)
    if not metrics:
        return None

    pr = metrics.get("PR", "")
    conf, integ, avail = _impact(metrics)
    scope_changed = metrics.get("S") == "C"
    high = {conf, integ, avail} & {"H"}

    if pr == "N":
        # 자격이 필요 없다. 얻는 것이 있어야 발판이 된다.
        gains = []
        if conf == "H":
            gains.append("정보 노출(C:H)")
        if integ == "H":
            gains.append("무결성 훼손(I:H)")
        if scope_changed:
            gains.append("범위 변경(S:C)")
        if not gains:
            return None
        return FOOTHOLD, f"자격 불필요(PR:N)이고 {' · '.join(gains)}"

    if pr in ("L", "H") and high:
        got = [name for name, value in
               (("기밀성", conf), ("무결성", integ), ("가용성", avail)) if value == "H"]
        need = "일반 사용자 권한(PR:L)" if pr == "L" else "관리자 권한(PR:H)"
        return ESCALATION, f"{need}을 요구하지만 {' · '.join(got)}에 높은 영향"

    return None


def _rank(intel: dict[str, Any]) -> tuple:
    """고를 순서. 실제 악용 → 악용 예측 → CVSS.

    `unknown` 은 0으로 내려앉는다. 그것이 "낮다"는 뜻은 아니지만, 확인된 것을
    먼저 보내는 편이 확인되지 않은 것을 먼저 보내는 것보다 낫다.
    """
    return (
        1 if intel.get("kev") == "true" else 0,
        1 if intel.get("exploit_available") == "true" else 0,
        float(intel.get("epss") or 0.0),
        float(intel.get("cvss_score") or 0.0),
    )


def pick(
    payloads: list[dict[str, Any]], *, limit: int = DEFAULT_LIMIT
) -> dict[str, list[Candidate]]:
    """finding payload 목록에서 두 갈래 후보를 고른다.

    같은 CVE 가 여러 패키지에서 나오면 한 번만 담는다 — 모델에게는 같은
    공개 취약점이고, 중복은 토큰만 먹는다.
    """
    picked: dict[str, dict[str, Candidate]] = {FOOTHOLD: {}, ESCALATION: {}}

    for payload in payloads:
        intel = payload.get("intel") or {}
        cve = intel.get("cve") or ""
        if not cve:
            continue
        verdict = classify(intel.get("cvss_vector") or "")
        if verdict is None:
            continue
        role, reason = verdict
        bucket = picked[role]
        candidate = Candidate(cve=cve, role=role, reason=reason, score=_rank(intel))
        existing = bucket.get(cve)
        if existing is None or candidate.score > existing.score:
            bucket[cve] = candidate

    return {
        role: sorted(bucket.values(), key=lambda c: c.score, reverse=True)[:limit]
        for role, bucket in picked.items()
    }


def summarize(picked: dict[str, list[Candidate]]) -> dict[str, Any]:
    """화면에 "무엇을 왜 골랐는지" 적기 위한 요약."""
    return {
        "counts": {role: len(items) for role, items in picked.items()},
        "roles": {
            role: [
                {"cve": c.cve, "reason": c.reason} for c in items
            ] for role, items in picked.items()
        },
        "labels": dict(ROLE_LABEL),
    }
