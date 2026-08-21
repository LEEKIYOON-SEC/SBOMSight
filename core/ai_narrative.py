"""AI 서술 계층 (Mode A) — 선택 기능.

흐름:
    Finding → [공개 계층만] VulnFact 조립 → 이그레스 가드 → Gemini
           → 표현 린트 → (위반 시 1회 재생성) → 여전히 위반이면 룰 문장으로 폴백

이 계층이 통째로 실패해도 보고서는 완결된다. 실패는 조용히 삼키지 않고
호출부에 알리되, 리포트 생성은 룰 기반으로 계속된다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from .audit import AuditLog
from .config import Config, get_config
from .gemini import GeminiClient, GeminiError, GeminiUnavailable
from .models import Finding
from .prompt import NARRATIVE_FIELDS
from .report import Narrative
from .sanitizer import EgressBlocked, EgressGuard
from .tone import ToneGuard
from .vulnfact import build_batch

logger = logging.getLogger(__name__)

# AI 응답에서 절대 받아들이지 않는 키. 모델이 넣어도 무시한다.
_IGNORED_KEYS = {
    "priority", "priority_reasons", "priority_label", "severity_rating",
    "risk_level", "verdict", "is_vulnerable", "update_available",
}


def _to_narrative(analysis: dict[str, Any]) -> Narrative:
    """모델 응답 하나를 Narrative로 옮긴다.

    우선순위성 필드는 여기서 버려진다. Narrative에 그 자리가 없으므로
    사실 옮길 방법도 없지만, 무시가 의도적임을 남겨 둔다.
    """
    for key in _IGNORED_KEYS:
        analysis.pop(key, None)

    return Narrative(
        technical_risk=str(analysis.get("technical_risk") or ""),
        attack_preconditions=tuple(str(x) for x in analysis.get("attack_preconditions") or ()),
        impact_types=tuple(str(x) for x in analysis.get("impact_types") or ()),
        exploitability_note=str(analysis.get("exploitability_note") or ""),
        response_rationale=str(analysis.get("response_rationale") or ""),
        recommendation_note=str(analysis.get("recommendation_note") or ""),
        source="ai",
    )


def narrative_to_dict(narrative: Narrative) -> dict[str, Any]:
    """저장용 직렬화. 우선순위성 필드는 애초에 존재하지 않는다."""
    return {
        "technical_risk": narrative.technical_risk,
        "attack_preconditions": list(narrative.attack_preconditions),
        "impact_types": list(narrative.impact_types),
        "exploitability_note": narrative.exploitability_note,
        "response_rationale": narrative.response_rationale,
        "recommendation_note": narrative.recommendation_note,
        "source": narrative.source,
    }


def narrative_from_dict(payload: dict[str, Any]) -> Narrative:
    """저장된 서술을 되살린다. 알 수 없는 키는 버린다."""
    return Narrative(
        technical_risk=str(payload.get("technical_risk") or ""),
        attack_preconditions=tuple(str(x) for x in payload.get("attack_preconditions") or ()),
        impact_types=tuple(str(x) for x in payload.get("impact_types") or ()),
        exploitability_note=str(payload.get("exploitability_note") or ""),
        response_rationale=str(payload.get("response_rationale") or ""),
        recommendation_note=str(payload.get("recommendation_note") or ""),
        source=str(payload.get("source") or "ai"),
    )


def _narrative_texts(narrative: Narrative) -> dict[str, str]:
    return {
        "technical_risk": narrative.technical_risk,
        "exploitability_note": narrative.exploitability_note,
        "response_rationale": narrative.response_rationale,
        "recommendation_note": narrative.recommendation_note,
    }


@dataclass(frozen=True)
class NarrativeRun:
    """서술 생성 1회의 결과와 그 경위.

    호출부(웹 UI)가 "몇 건에 적용됐고, 무엇이 왜 반영되지 않았는지"를 사람에게
    그대로 보여 줄 수 있어야 한다. 조용히 일부만 적용하고 끝내면 독자는 자기가
    읽는 문장이 AI 것인지 룰 것인지 알 수 없다.
    """

    narratives: dict[str, Narrative] = dataclass_field(default_factory=dict)
    rejected: tuple[dict[str, Any], ...] = ()      # {"cve": ..., "rules": [...]}
    errors: tuple[str, ...] = ()
    model: str = ""
    requested: int = 0
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": len(self.narratives),
            "requested": self.requested,
            "rejected": list(self.rejected),
            "errors": list(self.errors),
            "model": self.model,
            "available": self.available,
        }


def run_narratives(
    findings: tuple[Finding, ...] | list[Finding],
    *,
    config: Config | None = None,
    scan_id: str = "",
) -> NarrativeRun:
    """선택된 finding들에 대해 AI 서술을 생성한다.

    전달되는 것은 `build_batch`가 공개 계층에서 조립한 VulnFact뿐이다.
    findings 자체는 이 함수 밖으로 나가지 않는다.
    """
    config = config or get_config()
    guard = EgressGuard.from_config(config)
    audit = AuditLog(config.audit_dir)
    client = GeminiClient(config, guard=guard, audit=audit)
    tone = ToneGuard.from_config(config)

    if not client.available():
        logger.info("AI가 비활성이거나 키가 없어 룰 기반 서술로 진행합니다.")
        return NarrativeRun(available=False)

    facts = build_batch(findings)
    if not facts:
        return NarrativeRun(requested=0)

    limit = guard.limits.get("max_facts_per_request") or len(facts)
    narratives: dict[str, Narrative] = {}
    rejected: list[dict[str, Any]] = []
    errors: list[str] = []
    model = ""

    for start in range(0, len(facts), limit):
        chunk = facts[start : start + limit]
        try:
            result = client.analyze(chunk, scan_id=scan_id)
        except EgressBlocked as blocked:
            # 가드가 막았다면 그것은 버그이거나 공격이다. 조용히 넘기지 않는다.
            logger.error("이그레스 가드가 전송을 차단했습니다: %s", blocked)
            raise
        except (GeminiUnavailable, GeminiError) as exc:
            logger.warning("AI 서술 생성 실패, 룰 기반으로 진행합니다: %s", exc)
            errors.append(str(exc))
            continue

        model = result.model
        for analysis in result.analyses:
            cve = str(analysis.get("cve") or "")
            if not cve:
                continue
            narrative = _to_narrative(dict(analysis))
            violations = tone.inspect(_narrative_texts(narrative))
            if violations:
                logger.warning(
                    "%s: 표현 정책 위반 %s — 해당 서술을 버리고 룰 문장을 사용합니다",
                    cve, [v.rule for v in violations],
                )
                rejected.append({"cve": cve, "rules": sorted({v.rule for v in violations})})
                continue
            narratives[cve] = narrative

    return NarrativeRun(
        narratives=narratives,
        rejected=tuple(rejected),
        errors=tuple(errors),
        model=model,
        requested=len(facts),
    )


def generate_narratives(
    findings: tuple[Finding, ...] | list[Finding],
    *,
    config: Config | None = None,
    scan_id: str = "",
) -> dict[str, Narrative]:
    """CVE ID → Narrative 매핑을 만든다. 실패하면 빈 dict를 돌려준다.

    빈 dict를 받은 ReportBuilder는 전 항목을 룰 문장으로 채운다 —
    AI 없이도 보고서가 완결된다는 전제가 여기서도 지켜진다.
    """
    return run_narratives(findings, config=config, scan_id=scan_id).narratives


def regenerate_with_tone_retry(
    client: GeminiClient,
    tone: ToneGuard,
    facts: list[dict[str, Any]],
    *,
    scan_id: str = "",
) -> dict[str, Narrative]:
    """표현 위반 시 1회 재생성한다.

    generate_narratives는 위반 항목을 버리는 쪽을 택한다(단순하고 안전).
    재생성이 필요한 경우 이 함수를 쓴다 — 위반한 CVE만 다시 요청한다.
    """
    narratives: dict[str, Narrative] = {}
    pending = facts

    for round_index in range(2):
        if not pending:
            break
        result = client.analyze(pending, scan_id=scan_id)
        retry: list[dict[str, Any]] = []
        by_cve = {f["cve"]: f for f in pending}

        for analysis in result.analyses:
            cve = str(analysis.get("cve") or "")
            narrative = _to_narrative(dict(analysis))
            if tone.inspect(_narrative_texts(narrative)):
                if round_index == 0 and cve in by_cve:
                    retry.append(by_cve[cve])
                continue
            narratives[cve] = narrative

        pending = retry

    return narratives
