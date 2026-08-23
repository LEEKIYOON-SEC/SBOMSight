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

from . import escalation
from .audit import AuditLog
from .config import Config, get_config
from .gemini import GeminiClient, GeminiError, GeminiUnavailable
from .models import Finding
from .prompt import NARRATIVE_FIELDS
from .report import Narrative
from .sanitizer import EgressBlocked, EgressGuard
from .tone import ToneGuard
from .vulnfact import build_batch, build_from_finding

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


# ---------------------------------------------------------------------------
# 연계 분석 — 패키지 묶음 단위
# ---------------------------------------------------------------------------


@dataclass
class ChainRun:
    """연계 분석 1회의 결과와 경위."""

    analyses: dict[str, str] = dataclass_field(default_factory=dict)  # 패키지명 → 서술
    rejected: tuple[dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    model: str = ""
    requested: int = 0
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": len(self.analyses),
            "requested": self.requested,
            "rejected": list(self.rejected),
            "errors": list(self.errors),
            "model": self.model,
            "available": self.available,
        }


def build_chain_groups(
    packages: list[Any],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """PackageGroup 목록을 전송 가능한 묶음 데이터로 옮긴다.

    돌려주는 것은 `(전송할 묶음, 묶음번호 → 패키지명)` 이다. **패키지명은 전송
    데이터에 들어가지 않는다** — advisory 가 지목한 패키지명은 이미 VulnFact 안에
    공개 데이터로 있지만, "이것들이 한 자산에 함께 설치되어 있다"는 사실 자체는
    내부 정보다. 되돌리는 표는 우리 쪽에만 남는다.

    취약점이 한 건뿐인 묶음은 보내지 않는다. 혼자서는 연쇄할 상대가 없다.
    """
    groups: list[dict[str, Any]] = []
    index: dict[str, str] = {}
    for number, group in enumerate(packages, 1):
        if group.cve_count < 2:
            continue
        key = f"group-{number}"
        index[key] = group.package
        groups.append({
            "group": key,
            "vulnerabilities": [
                build_vuln_fact_from_report(item) for item in group.findings
            ],
        })
    return groups, index


def build_vuln_fact_from_report(item: Any) -> dict[str, Any]:
    """FindingReport 에서 공개 계층만 뽑는다.

    `core.vulnfact.build_vuln_fact` 와 같은 원칙이지만 입력이 보고서 항목이다.
    보고서를 다시 만들지 않고 이미 조립된 것에서 꺼내 쓰기 위한 것이며,
    **화이트리스트로 만든다** — 필드를 빠뜨려서 새는 것이 아니라, 적지 않은
    필드는 애초에 들어갈 자리가 없다.
    """
    o = item.overview
    e = item.exploitability
    return {
        "cve": item.cve,
        "cvss_score": o.get("cvss_score"),
        "cvss_vector": o.get("cvss_vector", ""),
        "severity": o.get("severity", ""),
        "cwe": list(o.get("cwe") or ()),
        "epss": e.get("epss"),
        "kev": e.get("kev", "unknown"),
        "exploit_available": e.get("exploit_available", "unknown"),
        "advisory_package": o.get("advisory_package", ""),
        "advisory_ecosystem": o.get("advisory_ecosystem", ""),
        "affected_version_range": o.get("affected_version_range", ""),
        "fixed_version": o.get("fixed_version", ""),
    }


def run_chain_analysis(
    packages: list[Any],
    *,
    config: Config | None = None,
    scan_id: str = "",
) -> ChainRun:
    """패키지 묶음별 연계 분석을 생성한다.

    전달되는 것은 VulnFact 뿐이고, 같은 이그레스 가드를 통과한다.
    """
    config = config or get_config()
    guard = EgressGuard.from_config(config)
    audit = AuditLog(config.audit_dir)
    client = GeminiClient(config, guard=guard, audit=audit)
    tone = ToneGuard.from_config(config)

    if not client.available():
        return ChainRun(available=False)

    groups, index = build_chain_groups(packages)
    if not groups:
        return ChainRun(requested=0)

    analyses: dict[str, str] = {}
    rejected: list[dict[str, Any]] = []
    errors: list[str] = []
    model = ""

    try:
        result = client.analyze_chains(groups, scan_id=scan_id)
    except EgressBlocked:
        raise
    except (GeminiUnavailable, GeminiError) as exc:
        logger.warning("연계 분석 생성 실패, 보고서는 연계 분석 없이 나갑니다: %s", exc)
        return ChainRun(requested=len(groups), errors=(str(exc),))

    model = result.model
    for chain in result.analyses:
        key = str(chain.get("group") or "")
        text = str(chain.get("analysis") or "").strip()
        package = index.get(key)
        if not package or not text:
            continue
        violations = tone.inspect({"chain": text})
        if violations:
            logger.warning(
                "%s: 표현 정책 위반 %s — 연계 분석을 버립니다",
                package, [v.rule for v in violations],
            )
            rejected.append({"package": package, "rules": sorted({v.rule for v in violations})})
            continue
        analyses[package] = text

    return ChainRun(
        analyses=analyses, rejected=tuple(rejected), errors=tuple(errors),
        model=model, requested=len(groups),
    )


# ---------------------------------------------------------------------------
# 연계 상승 — 패키지를 가로지른다
# ---------------------------------------------------------------------------


@dataclass
class EscalationRun:
    """연계 상승 분석 1회의 결과와 경위."""

    chains: tuple[dict[str, Any], ...] = ()
    note: str = ""
    scope: dict[str, Any] = dataclass_field(default_factory=dict)
    rejected: tuple[dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    model: str = ""
    requested: int = 0
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "chains": list(self.chains),
            "note": self.note,
            "scope": self.scope,
            "found": len(self.chains),
            "requested": self.requested,
            "rejected": list(self.rejected),
            "errors": list(self.errors),
            "model": self.model,
            "available": self.available,
        }


def run_escalation_analysis(
    payloads: list[dict[str, Any]],
    *,
    limit: int = escalation.DEFAULT_LIMIT,
    config: Config | None = None,
    scan_id: str = "",
) -> EscalationRun:
    """저위험 조합이 고위험으로 상승하는 경로를 찾는다.

    **후보 선정은 우리가 한다.** CVSS 벡터에서 `PR:N`(발판)과 `PR:L/H` + 높은
    영향(상승)을 읽어 두 갈래로 나누고, KEV·EPSS·CVSS 순으로 상한만큼 고른다.
    AI 는 고른 것들 사이의 연쇄 논리를 서술할 뿐이며, 등급을 매기지 않는다.

    나가는 것은 여전히 VulnFact 뿐이다 — 어느 자산의 것인지, 실제로 함께
    설치되어 있는지는 전달되지 않는다.
    """
    config = config or get_config()
    guard = EgressGuard.from_config(config)
    audit = AuditLog(config.audit_dir)
    client = GeminiClient(config, guard=guard, audit=audit)
    tone = ToneGuard.from_config(config)

    picked = escalation.pick(payloads, limit=limit)
    scope = escalation.summarize(picked)
    by_cve = {(p.get("intel") or {}).get("cve"): p for p in payloads}

    def facts_for(role: str) -> list[dict[str, Any]]:
        out = []
        for candidate in picked[role]:
            payload = by_cve.get(candidate.cve)
            if payload is not None:
                out.append(build_vuln_fact_from_payload(payload))
        return out

    footholds = facts_for(escalation.FOOTHOLD)
    escalations = facts_for(escalation.ESCALATION)
    requested = len(footholds) + len(escalations)

    if not client.available():
        return EscalationRun(available=False, scope=scope, requested=requested)
    if not footholds or not escalations:
        # 한 갈래만 있으면 엮을 상대가 없다. 모델을 부르지 않는다.
        return EscalationRun(
            scope=scope, requested=requested,
            note="연쇄를 이루려면 자격 없이 성립하는 취약점과 자격을 요구하는 "
                 "취약점이 모두 있어야 하는데, 한쪽만 확인되었습니다.",
        )

    try:
        result = client.analyze_escalation(footholds, escalations, scan_id=scan_id)
    except EgressBlocked:
        raise
    except (GeminiUnavailable, GeminiError) as exc:
        logger.warning("연계 상승 분석 실패: %s", exc)
        return EscalationRun(scope=scope, requested=requested, errors=(str(exc),))

    known = {f["cve"] for f in footholds} | {f["cve"] for f in escalations}
    chains: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for chain in result.analyses:
        steps = [s for s in (chain.get("steps") or []) if str(s.get("cve") or "") in known]
        if len(steps) < 2:
            # 두 단계가 안 되면 연쇄가 아니다. 보낸 적 없는 CVE 가 섞였으면 버린다.
            continue
        text = " ".join(str(chain.get(k) or "") for k in ("title", "outcome", "escalation"))
        text += " " + " ".join(str(s.get("why") or "") for s in steps)
        violations = tone.inspect({"escalation": text})
        if violations:
            logger.warning("표현 정책 위반 %s — 이 연쇄를 버립니다",
                           [v.rule for v in violations])
            rejected.append({
                "title": str(chain.get("title") or ""),
                "rules": sorted({v.rule for v in violations}),
            })
            continue
        chains.append({
            "title": str(chain.get("title") or ""),
            "steps": [{
                "cve": str(s.get("cve") or ""),
                "role": str(s.get("role") or ""),
                "why": str(s.get("why") or ""),
            } for s in steps],
            "outcome": str(chain.get("outcome") or ""),
            "escalation": str(chain.get("escalation") or ""),
            "confidence": str(chain.get("confidence") or "보통"),
            "confidence_reason": str(chain.get("confidence_reason") or ""),
        })

    return EscalationRun(
        chains=tuple(chains),
        note=str(result.extra.get("note") or ""),
        scope=scope,
        rejected=tuple(rejected),
        model=result.model,
        requested=requested,
    )


def build_vuln_fact_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """저장된 finding payload 에서 VulnFact 를 만든다.

    **직접 조립하지 않는다.** payload 를 Finding 으로 되살린 뒤
    `core.vulnfact.build_from_finding` 에 넘긴다. 화이트리스트가 두 벌이 되면
    한쪽만 고쳐지는 날이 오고, 실제로 처음 짤 때 `fix_state`(금칙 필드)를
    넣어 이그레스 가드에 막혔다. 조립기는 하나여야 한다.
    """
    from .cli import revive_finding

    return build_from_finding(revive_finding(payload))
