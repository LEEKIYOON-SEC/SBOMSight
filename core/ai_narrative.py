"""AI 서술 계층 (Mode A) — 선택 기능.

흐름:
    Finding → [공개 계층만] VulnFact 조립 → 이그레스 가드 → Gemini
           → 표현 린트 → (위반 시 1회 재생성) → 여전히 위반이면 룰 문장으로 폴백

이 계층이 통째로 실패해도 보고서는 완결된다. 실패는 조용히 삼키지 않고
호출부에 알리되, 리포트 생성은 룰 기반으로 계속된다.
"""

from __future__ import annotations

import logging
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


def _narrative_texts(narrative: Narrative) -> dict[str, str]:
    return {
        "technical_risk": narrative.technical_risk,
        "exploitability_note": narrative.exploitability_note,
        "response_rationale": narrative.response_rationale,
        "recommendation_note": narrative.recommendation_note,
    }


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
    config = config or get_config()
    guard = EgressGuard.from_config(config)
    audit = AuditLog(config.audit_dir)
    client = GeminiClient(config, guard=guard, audit=audit)
    tone = ToneGuard.from_config(config)

    if not client.available():
        logger.info("AI가 비활성이거나 키가 없어 룰 기반 서술로 진행합니다.")
        return {}

    facts = build_batch(findings)
    if not facts:
        return {}

    limit = guard.limits.get("max_facts_per_request") or len(facts)
    narratives: dict[str, Narrative] = {}

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
            continue

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
                continue
            narratives[cve] = narrative

    return narratives


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
