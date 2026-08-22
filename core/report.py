"""취약점 대응 검토 보고서 조립.

보고서는 **"AI가 쓴 취약점 보고서"가 아니라 "공개 취약점 데이터 + 로컬
SBOM/Grype 결과 + (선택) AI 자연어 분석"** 으로 읽혀야 한다. 그래서
모든 항목에 근거 배지와 출처가 붙고, AI가 쓴 문장과 룰이 만든 문장을
구분해 표시한다(`Narrative.source`).

절 구성 (CVE 단위):
    ① 취약점 개요        공개 데이터
    ② 기술적 위험성      CVSS 벡터·CWE(룰) + AI 서술
    ③ 악용 가능성        공개 데이터 (EPSS · KEV · Exploit, 출처 포함)
    ④ 대응 필요성 분석   우선순위=룰, 서술=AI
    ⑤ 권고사항          Playbook(룰) + AI 부연
    ⑥ 근거 및 Reference  공개 데이터

    [로컬 분석 정보]     AI 미전달 — 설치 버전, FixAnalysis, Grype 탐지 근거

AI가 없어도 ②④⑤가 룰 문장으로 채워져 보고서가 완결된다.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from . import cvss as cvss_mod
from .config import Config, get_config
from .models import (
    ExploitMaturity,
    Finding,
    Priority,
    ScanResult,
    Severity,
    Ternary,
    to_jsonable,
)
from .playbooks import PlaybookLibrary, Recommendation
from .ruleengine import RuleEngine, sort_key

# 보고서 머리말. 이 도구의 성격을 읽는 사람이 오해하지 않도록 항상 싣는다.
DISCLAIMER = (
    "이 보고서는 공개된 취약점 데이터(CVSS · EPSS · CISA KEV · 공개 Exploit)와 "
    "로컬 SBOM/Grype 탐지 결과를 결합해 **대응 여부를 검토하기 위한 근거**를 "
    "정리한 것이다. 여기서 제시하는 '대응 검토 우선순위'는 아래 명시된 정책 룰을 "
    "공개 데이터에 적용한 결과이며, 조직 내부의 실제 위험도와 최종적인 패치 여부는 "
    "자산의 노출 경로·보상 통제·업무 영향을 함께 고려해 보안담당자가 판단한다."
)

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.NEGLIGIBLE: "Negligible",
    Severity.UNKNOWN: "미확인",
}

_MATURITY_LABEL = {
    ExploitMaturity.WEAPONIZED: "무기화 (즉시 사용 가능한 공격 도구 공개)",
    ExploitMaturity.PUBLIC_POC: "공개 PoC",
    ExploitMaturity.NONE: "확인된 공개 exploit 없음",
    ExploitMaturity.UNKNOWN: "미확인",
}

_EXPLOIT_SOURCE_LABEL = {
    "exploit_db": "Exploit-DB",
    "metasploit": "Metasploit",
    "github_poc": "GitHub PoC",
    "nuclei": "Nuclei 템플릿",
}


# ---------------------------------------------------------------------------
# AI 경계 (출력 측)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Narrative:
    """자연어 서술. AI가 채우거나, 없으면 룰이 채운다.

    `source`가 "rule"이면 결정론적으로 생성된 문장이고 "ai"면 모델이 쓴
    문장이다. 보고서에 이 구분을 표시해 독자가 무엇을 읽고 있는지 알게 한다.

    AI는 이 구조 바깥의 값(우선순위·판정)을 채울 수 없다. 병합 단계에서
    무시된다.
    """

    technical_risk: str = ""
    attack_preconditions: tuple[str, ...] = ()
    impact_types: tuple[str, ...] = ()
    exploitability_note: str = ""
    response_rationale: str = ""
    recommendation_note: str = ""
    source: str = "rule"


@dataclass(frozen=True)
class EvidenceBadge:
    """모든 CVE 항목에 고정 노출되는 근거 배지.

    숫자를 보여 주지 않으면 독자가 판정을 검증할 수 없다.
    """

    cvss: str = "미확인"
    epss: str = "미확인"
    kev: str = "미확인"
    exploit: str = "미확인"
    fixed_version: str = "없음"
    verdict: str = ""
    policy: str = ""


@dataclass(frozen=True)
class FindingReport:
    """CVE 한 건에 대한 보고서 항목."""

    cve: str
    priority: Priority
    priority_label: str
    aliases: tuple[str, ...]
    badge: EvidenceBadge
    overview: dict[str, Any]            # ①
    technical_risk: dict[str, Any]      # ②
    exploitability: dict[str, Any]      # ③
    response_rationale: dict[str, Any]  # ④
    recommendation: Recommendation      # ⑤
    references: tuple[dict[str, str], ...]  # ⑥
    local_analysis: dict[str, Any]      # [로컬 분석 정보] — AI 미전달
    flags: tuple[dict[str, str], ...]
    narrative_source: str


@dataclass
class Report:
    generated_at: str
    scan: dict[str, Any]
    summary: dict[str, Any]
    findings: list[FindingReport] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    enrichment: dict[str, Any] = field(default_factory=dict)
    disclaimer: str = DISCLAIMER
    ai_used: bool = False


# ---------------------------------------------------------------------------
# 룰 기반 서술 — AI가 없을 때 ②④⑤를 채운다
# ---------------------------------------------------------------------------


def _rule_technical_risk(finding: Finding) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    facts = cvss_mod.describe(finding.intel.cvss_vector)
    impacts = cvss_mod.classify_impact(finding.intel.cvss_vector, finding.intel.cwe)

    if not facts.parsed:
        text = (
            "CVSS 벡터를 확보하지 못해 공격 조건을 구조적으로 분석할 수 없다. "
            "아래 Reference의 벤더 advisory에서 직접 확인이 필요하다."
        )
        return text, (), impacts

    pieces = []
    if facts.remote_unauthenticated:
        pieces.append(
            "CVSS 벡터상 네트워크를 통해 인증이나 사용자 조작 없이 접근 가능한 형태로 분류된다"
        )
    else:
        conditions = []
        if facts.attack_vector:
            conditions.append(f"공격 경로는 {facts.attack_vector}")
        if facts.privileges_required and facts.privileges_required != "불필요":
            conditions.append(f"{facts.privileges_required}")
        if facts.user_interaction and facts.user_interaction != "불필요":
            conditions.append(f"{facts.user_interaction}")
        pieces.append("CVSS 벡터상 " + ", ".join(conditions) + "한 조건에서 악용될 수 있는 형태로 분류된다")

    if impacts:
        pieces.append("공격이 성립할 경우 " + " · ".join(impacts) + "이 제시된다")
    if finding.intel.cwe:
        labels = [cvss_mod.cwe_label(c) for c in finding.intel.cwe]
        pieces.append("취약점 유형은 " + ", ".join(labels) + "으로 분류되어 있다")

    return ". ".join(pieces) + ".", facts.preconditions, impacts


def _rule_exploitability_note(finding: Finding) -> str:
    intel = finding.intel
    parts: list[str] = []

    if intel.kev is Ternary.TRUE:
        added = f" ({intel.kev_date_added} 등재)" if intel.kev_date_added else ""
        parts.append(f"CISA가 실제 악용을 확인해 KEV 카탈로그에 등재한 취약점이다{added}")
        if intel.kev_ransomware_use and intel.kev_ransomware_use.lower() == "known":
            parts.append("랜섬웨어 캠페인에서의 사용이 확인되었다")
    elif intel.kev is Ternary.FALSE:
        parts.append("CISA KEV 카탈로그에는 등재되어 있지 않다")
    else:
        parts.append("CISA KEV 등재 여부를 확인하지 못했다")

    if intel.epss is not None:
        # 숫자 뒤 조사(로/으로)는 읽는 방식에 따라 갈리므로 조사를 붙이지 않는다.
        sentence = (
            f"EPSS 점수는 {intel.epss:.4f} — 향후 30일 내 악용 시도가 관측될 확률이 "
            f"{intel.epss * 100:.1f}%로 추정된다"
        )
        if intel.epss_percentile is not None:
            # percentile은 '이 CVE보다 낮은 비율'이므로 상위 비율은 그 여집합이다.
            top = (1 - intel.epss_percentile) * 100
            sentence += f" (전체 CVE 중 상위 {top:.1f}% 구간)"
        parts.append(sentence)
    else:
        parts.append("EPSS 점수를 확보하지 못했다 (악용 가능성이 낮다는 뜻은 아니다)")

    if intel.exploit_available is Ternary.TRUE:
        names = sorted({_EXPLOIT_SOURCE_LABEL.get(s.source, s.source) for s in intel.exploit_sources})
        maturity = _MATURITY_LABEL.get(intel.exploit_maturity, "미확인")
        parts.append(
            f"공개된 exploit/PoC가 확인된다 ({', '.join(names)}). "
            f"성숙도 분류: {maturity}"
        )
    elif intel.exploit_available is Ternary.FALSE:
        parts.append("조회한 공개 exploit 저장소에서는 exploit/PoC가 확인되지 않았다")
    else:
        parts.append("공개 exploit 존재 여부를 확인하지 못했다 (없다는 뜻은 아니다)")

    return ". ".join(parts) + "."


def _rule_response_rationale(finding: Finding, engine: RuleEngine) -> str:
    verdict = finding.verdict
    if verdict is None:
        return "우선순위 판정이 수행되지 않았다."

    level = engine.describe_level(verdict.priority)
    label = level.get("label", verdict.priority.value)

    if verdict.fired_rules:
        grounds = ", ".join(r.explain or r.name for r in verdict.fired_rules)
        head = (
            f"{grounds}가 관측되어 적용 정책상 '{verdict.priority.value} {label}' 구간으로 분류된다"
        )
    else:
        head = (
            f"우선순위 상향 조건에 해당하는 신호가 관측되지 않아 "
            f"'{verdict.priority.value} {label}' 구간으로 분류된다"
        )

    tail: list[str] = []
    if "no_fix_available" in verdict.flags:
        tail.append(
            "공개된 수정 버전이 없어 업데이트로는 해소할 수 없으므로 완화 방안 검토가 함께 필요하다"
        )
    if "stale_snapshot" in verdict.flags:
        tail.append("판정에 사용한 위협정보 스냅샷이 오래되어 최신 데이터로 재확인이 권고된다")

    sentences = [head + "."]
    sentences.extend(t + "." for t in tail)
    sentences.append(
        "해당 구성요소의 노출 경로와 업무 영향을 함께 고려해 대응 시점을 결정하는 것이 권고된다."
    )
    return " ".join(sentences)


# ---------------------------------------------------------------------------
# 배지 · 절 구성
# ---------------------------------------------------------------------------


def _build_badge(finding: Finding, engine: RuleEngine) -> EvidenceBadge:
    intel = finding.intel
    verdict = finding.verdict

    cvss = "미확인"
    if intel.cvss_score is not None:
        vector = f" ({intel.cvss_vector})" if intel.cvss_vector else ""
        cvss = f"{intel.cvss_score:g} / {_SEVERITY_LABEL.get(intel.severity, '미확인')}{vector}"

    epss = "미확인"
    if intel.epss is not None:
        percentile = f" · 백분위 {intel.epss_percentile:.4f}" if intel.epss_percentile is not None else ""
        snapshot = f" · 기준일 {intel.epss_snapshot_date}" if intel.epss_snapshot_date else ""
        epss = f"{intel.epss:.4f}{percentile}{snapshot}"

    if intel.kev is Ternary.TRUE:
        kev = f"YES (등재 {intel.kev_date_added})" if intel.kev_date_added else "YES"
        if intel.kev_ransomware_use and intel.kev_ransomware_use.lower() == "known":
            kev += " · 랜섬웨어 사용 확인"
    elif intel.kev is Ternary.FALSE:
        kev = "NO"
    else:
        kev = "미확인"

    if intel.exploit_available is Ternary.TRUE:
        refs = ", ".join(
            f"{_EXPLOIT_SOURCE_LABEL.get(s.source, s.source)} {s.ref}" for s in intel.exploit_sources
        )
        exploit = f"YES ({_MATURITY_LABEL.get(intel.exploit_maturity, '')}" + (f" · {refs})" if refs else ")")
    elif intel.exploit_available is Ternary.FALSE:
        exploit = "NO (조회한 공개 저장소 기준)"
    else:
        exploit = "미확인"

    verdict_text = ""
    policy_text = ""
    if verdict is not None:
        level = engine.describe_level(verdict.priority)
        grounds = ", ".join(r.name for r in verdict.fired_rules) or "기본 등급"
        verdict_text = f"{verdict.priority.value} {level.get('label', '')} ← {grounds}"
        policy_text = f"{'+'.join(engine.policy.sources)} v{verdict.policy_version} (sha256:{verdict.policy_sha256[:12]})"

    return EvidenceBadge(
        cvss=cvss,
        epss=epss,
        kev=kev,
        exploit=exploit,
        fixed_version=finding.advisory.fixed_version or "없음",
        verdict=verdict_text,
        policy=policy_text,
    )


def _build_references(finding: Finding) -> tuple[dict[str, str], ...]:
    """⑥ 근거 및 Reference. 출처 없는 주장은 싣지 않는다."""
    refs: list[dict[str, str]] = []
    cve = finding.intel.cve

    if cve.upper().startswith("CVE-"):
        refs.append({"source": "NVD", "title": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
        refs.append(
            {"source": "FIRST EPSS", "title": f"{cve} EPSS", "url": f"https://api.first.org/data/v1/epss?cve={cve}"}
        )
    if finding.intel.kev is Ternary.TRUE:
        refs.append(
            {
                "source": "CISA KEV",
                "title": "Known Exploited Vulnerabilities Catalog",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )
    for source in finding.intel.exploit_sources:
        label = _EXPLOIT_SOURCE_LABEL.get(source.source, source.source)
        url = ""
        if source.source == "exploit_db" and source.ref.startswith("EDB-"):
            url = f"https://www.exploit-db.com/exploits/{source.ref[4:]}"
        elif source.source == "metasploit":
            url = "https://github.com/rapid7/metasploit-framework"
        refs.append({"source": label, "title": source.ref, "url": url})

    seen: set[str] = set()
    for url in finding.intel.references:
        if url in seen:
            continue
        seen.add(url)
        label = "Vendor Advisory"
        if "nvd.nist.gov" in url:
            label = "NVD"
        elif "cisa.gov" in url:
            label = "CISA"
        elif "github.com/advisories" in url:
            label = "GitHub Security Advisory"
        elif "access.redhat.com" in url:
            label = "Red Hat Advisory"
        refs.append({"source": label, "title": url, "url": url})

    deduped: list[dict[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for ref in refs:
        key = (ref["source"], ref.get("url") or ref["title"])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        deduped.append(ref)
    return tuple(deduped)


def _build_local_analysis(finding: Finding) -> dict[str, Any]:
    """[로컬 분석 정보] — AI에 절대 전달되지 않는 영역."""
    fix = finding.fix
    return {
        "ai_transmitted": False,
        "installed_package": finding.installed.name,
        "installed_version": finding.installed.version,
        "package_type": finding.installed.type,
        "purl": finding.installed.purl,
        "locations": list(finding.installed.locations),
        "found_in_sbom": True,
        "fix_analysis": {
            "installed_version": fix.installed_version if fix else "",
            "fixed_version": fix.fixed_version if fix else "",
            "comparator": fix.comparator if fix else "",
            "is_vulnerable": fix.is_vulnerable.value if fix else "unknown",
            "update_available": fix.update_available.value if fix else "unknown",
            "fix_state": fix.fix_state.value if fix else "unknown",
            "version_gap": fix.version_gap.value if fix else "unknown",
            "reason": fix.reason if fix else "",
        },
        "detection": {
            "matcher": finding.detection.matcher,
            "match_type": finding.detection.match_type,
            "namespace": finding.detection.namespace,
            "search_criteria": finding.detection.search_criteria,
        },
    }


# ---------------------------------------------------------------------------
# 조립
# ---------------------------------------------------------------------------


class ReportBuilder:
    def __init__(
        self,
        config: Config | None = None,
        engine: RuleEngine | None = None,
        playbooks: PlaybookLibrary | None = None,
    ):
        self.config = config or get_config()
        self.engine = engine or RuleEngine.from_config(self.config)
        self.playbooks = playbooks or PlaybookLibrary.from_config(self.config)

    def build(
        self,
        result: ScanResult,
        *,
        narratives: dict[str, Narrative] | None = None,
    ) -> Report:
        """스캔 결과를 보고서로 옮긴다.

        narratives: CVE ID → AI가 생성한 서술. 없으면 전부 룰 문장으로 채운다.
                    이 인자가 비어 있어도 보고서는 완결된다.
        """
        narratives = narratives or {}
        findings = sorted(result.findings, key=sort_key)
        items = [self._build_finding(f, narratives.get(f.intel.cve)) for f in findings]

        return Report(
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            scan=to_jsonable(result.metadata),
            summary=self._summarize(findings),
            findings=items,
            policy=result.policy or {
                "version": self.engine.policy.version,
                "sha256": self.engine.policy.sha256,
                "sources": list(self.engine.policy.sources),
                "label": self.engine.policy.label,
            },
            enrichment=result.enrichment,
            ai_used=any(i.narrative_source == "ai" for i in items),
        )

    def _build_finding(self, finding: Finding, ai: Narrative | None) -> FindingReport:
        rule_text, preconditions, impacts = _rule_technical_risk(finding)
        rule_exploit = _rule_exploitability_note(finding)
        rule_rationale = _rule_response_rationale(finding, self.engine)

        # AI 서술이 있으면 얹고, 없으면 룰 문장을 쓴다. 어느 쪽이든 절은 채워진다.
        narrative = ai or Narrative(
            technical_risk=rule_text,
            attack_preconditions=preconditions,
            impact_types=impacts,
            exploitability_note=rule_exploit,
            response_rationale=rule_rationale,
            source="rule",
        )

        verdict = finding.verdict
        priority = verdict.priority if verdict else Priority.P3
        level = self.engine.describe_level(priority)

        recommendation = self.playbooks.build(
            ecosystem=finding.advisory.advisory_ecosystem or finding.installed.type,
            package=finding.advisory.advisory_package,
            installed_version=finding.installed.version,
            fixed_version=finding.advisory.fixed_version,
            cve=finding.intel.cve,
            os_family=finding.advisory.os_family,
        )

        return FindingReport(
            cve=finding.intel.cve,
            priority=priority,
            priority_label=level.get("label", priority.value),
            aliases=finding.intel.aliases,
            badge=_build_badge(finding, self.engine),
            overview={
                "cve": finding.intel.cve,
                "aliases": list(finding.intel.aliases),
                "advisory_package": finding.advisory.advisory_package,
                "advisory_ecosystem": finding.advisory.advisory_ecosystem,
                "affected_version_range": finding.advisory.affected_version_range or "(범위 미공개)",
                "fixed_version": finding.advisory.fixed_version or "(없음)",
                "fix_state": finding.advisory.fix_state.value,
                "severity": _SEVERITY_LABEL.get(finding.intel.severity, "미확인"),
                "cvss_score": finding.intel.cvss_score,
                "cvss_vector": finding.intel.cvss_vector,
                "cvss_version": finding.intel.cvss_version,
                "cwe": [cvss_mod.cwe_label(c) for c in finding.intel.cwe],
                "published": finding.intel.published,
                "description": finding.intel.description,
                "os_family": finding.advisory.os_family,
            },
            technical_risk={
                "narrative": narrative.technical_risk or rule_text,
                "preconditions": list(narrative.attack_preconditions or preconditions),
                "impact_types": list(narrative.impact_types or impacts),
                "cwe": [cvss_mod.cwe_label(c) for c in finding.intel.cwe],
            },
            exploitability={
                "epss": finding.intel.epss,
                "epss_percentile": finding.intel.epss_percentile,
                "epss_snapshot_date": finding.intel.epss_snapshot_date,
                "kev": finding.intel.kev.value,
                "kev_date_added": finding.intel.kev_date_added,
                "kev_ransomware_use": finding.intel.kev_ransomware_use,
                "exploit_available": finding.intel.exploit_available.value,
                "exploit_maturity": finding.intel.exploit_maturity.value,
                "exploit_maturity_label": _MATURITY_LABEL.get(finding.intel.exploit_maturity, "미확인"),
                "exploit_sources": [
                    {
                        "source": s.source,
                        "label": _EXPLOIT_SOURCE_LABEL.get(s.source, s.source),
                        "ref": s.ref,
                        "note": s.note,
                    }
                    for s in finding.intel.exploit_sources
                ],
                "published": finding.intel.published,
                "narrative": narrative.exploitability_note or rule_exploit,
            },
            response_rationale={
                "priority": priority.value,
                "priority_label": level.get("label", priority.value),
                "priority_description": level.get("description", ""),
                "fired_rules": [
                    {"name": r.name, "explain": r.explain} for r in (verdict.fired_rules if verdict else ())
                ],
                "narrative": narrative.response_rationale or rule_rationale,
            },
            recommendation=recommendation,
            references=_build_references(finding),
            local_analysis=_build_local_analysis(finding),
            flags=tuple(self.engine.describe_flag(f) for f in (verdict.flags if verdict else ())),
            narrative_source=narrative.source,
        )

    def _summarize(self, findings: Iterable[Finding]) -> dict[str, Any]:
        findings = list(findings)
        priorities = Counter(f.verdict.priority.value for f in findings if f.verdict)
        return {
            "total": len(findings),
            "by_priority": {p: priorities.get(p, 0) for p in ("P0", "P1", "P2", "P3")},
            "priority_labels": {
                p: self.engine.describe_level(Priority(p)).get("label", p)
                for p in ("P0", "P1", "P2", "P3")
            },
            "vulnerable_confirmed": sum(
                1 for f in findings if f.fix and f.fix.is_vulnerable is Ternary.TRUE
            ),
            "vulnerable_unconfirmed": sum(
                1 for f in findings if f.fix and f.fix.is_vulnerable is Ternary.UNKNOWN
            ),
            "update_available": sum(
                1 for f in findings if f.fix and f.fix.update_available is Ternary.TRUE
            ),
            "no_fix_available": sum(
                1 for f in findings if f.verdict and "no_fix_available" in f.verdict.flags
            ),
            "kev_listed": sum(1 for f in findings if f.intel.kev is Ternary.TRUE),
            "exploit_available": sum(
                1 for f in findings if f.intel.exploit_available is Ternary.TRUE
            ),
            "affected_packages": len({f.installed.name for f in findings}),
        }
