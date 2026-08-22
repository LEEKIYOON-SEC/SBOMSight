"""대응 검토 우선순위 판정.

**결정론적이다.** 같은 입력에 같은 정책이면 언제나 같은 결과가 나오고,
어떤 룰이 발화했는지가 함께 나온다. AI는 이 판정에 관여하지 않는다 —
입력으로 받지도, 산출하지도 않는다.

산출물 `RuleVerdict`는 로컬 전용이다. 리포트에는 실리지만 이그레스
경계를 넘지 않는다.

용어에 유의: 여기서 나오는 것은 '위험도'가 아니라 '대응 검토 우선순위'다.
공개 데이터에 정책 룰을 적용한 결과일 뿐이며, 우리 환경에서의 실제 위험도와
패치 여부는 보안담당자가 판단한다.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config, get_config
from .models import (
    FiredRule,
    Finding,
    Priority,
    RuleVerdict,
    Ternary,
)
from .policy import LoadedPolicy, load as load_policy

_MISSING = object()


# ---------------------------------------------------------------------------
# 평가 컨텍스트
# ---------------------------------------------------------------------------


def build_context(finding: Finding) -> dict[str, Any]:
    """Finding에서 룰이 참조하는 평면 딕셔너리를 만든다.

    우선순위 `levels`는 **공개 신호만** 참조하도록 정책을 작성한다
    (cvss/epss/kev/exploit). 로컬 사실(fix_state, is_vulnerable,
    update_available)은 `flags` 쪽에서만 쓴다. 그래야 우선순위가 공개
    데이터만으로 설명 가능하고, 리포트를 읽는 사람이 근거를 따라갈 수 있다.
    """
    intel = finding.intel
    fix = finding.fix
    return {
        # 공개 신호
        "cvss_score": intel.cvss_score,
        "severity": intel.severity.value,
        "epss": intel.epss,
        "kev": intel.kev.value,
        "exploit_available": intel.exploit_available.value,
        "exploit_maturity": intel.exploit_maturity.value,
        # 로컬 사실 — flags 전용
        "fix_state": (fix.fix_state.value if fix else "unknown"),
        "is_vulnerable": (fix.is_vulnerable.value if fix else "unknown"),
        "update_available": (fix.update_available.value if fix else "unknown"),
        # 신선도
        "epss_snapshot_date": intel.epss_snapshot_date,
        "kev_snapshot_date": intel.kev_snapshot_date,
    }


# ---------------------------------------------------------------------------
# 연산자
# ---------------------------------------------------------------------------


def _is_missing(value: Any) -> bool:
    return value is None or value is _MISSING or value == ""


def _evaluate(spec: dict[str, Any], context: dict[str, Any]) -> tuple[bool, str]:
    """신호 하나를 평가해 (발화 여부, 근거 문자열)을 돌려준다.

    근거 문자열은 리포트에 그대로 실린다: "EPSS 높음 (0.9134 ≥ 0.5)".
    숫자를 보여 주지 않으면 사람이 판정을 검증할 수 없다.
    """
    field = spec.get("field", "")
    op = spec.get("op", "")
    threshold = spec.get("value")
    value = context.get(field, _MISSING)
    label = spec.get("label") or field

    if op == "is_missing":
        return _is_missing(value), f"{label} (값 없음)" if _is_missing(value) else ""
    if op == "is_unknown":
        return value == "unknown", f"{label}" if value == "unknown" else ""
    if op == "is_true":
        return value == "true" or value is True, f"{label}" if (value == "true" or value is True) else ""
    if op == "is_false":
        return value == "false" or value is False, f"{label}" if (value == "false" or value is False) else ""

    # 값이 없으면 비교 연산은 발화하지 않는다. "데이터가 없음"과 "낮음"은
    # 다른 이야기이며, 전자는 flags(unknown_*)로 따로 표기된다.
    if _is_missing(value) or value == "unknown":
        return False, ""

    if op == "in":
        options = threshold if isinstance(threshold, list) else [threshold]
        hit = value in options
        return hit, f"{label} ({value})" if hit else ""
    if op == "==":
        hit = value == threshold
        return hit, f"{label} ({value})" if hit else ""
    if op == "!=":
        hit = value != threshold
        return hit, f"{label} ({value})" if hit else ""

    try:
        numeric = float(value)
        limit = float(threshold)
    except (TypeError, ValueError):
        return False, ""

    symbol = {">=": "≥", ">": ">", "<=": "≤", "<": "<"}.get(op)
    if symbol is None:
        return False, ""
    hit = {
        ">=": numeric >= limit,
        ">": numeric > limit,
        "<=": numeric <= limit,
        "<": numeric < limit,
    }[op]
    formatted = f"{numeric:g}"
    return hit, f"{label} ({formatted} {symbol} {limit:g})" if hit else ""


# ---------------------------------------------------------------------------
# 엔진
# ---------------------------------------------------------------------------


class RuleEngine:
    def __init__(self, policy: LoadedPolicy):
        self.policy = policy
        self.signals: dict[str, dict[str, Any]] = policy.data.get("signals") or {}
        self.levels: list[dict[str, Any]] = policy.data.get("levels") or []
        self.flag_specs: dict[str, dict[str, Any]] = policy.data.get("flags") or {}

    @classmethod
    def from_config(cls, config: Config | None = None) -> "RuleEngine":
        config = config or get_config()
        return cls(
            load_policy(
                config.rules_dir / "priority.json",
                config.config_dir / "priority.local.json",
            )
        )

    # -- 개별 판정 --------------------------------------------------------

    def evaluate(self, finding: Finding, *, stale_days: int = 7) -> RuleVerdict:
        context = build_context(finding)

        fired_signals: dict[str, str] = {}
        for name, spec in self.signals.items():
            hit, explain = _evaluate(spec, context)
            if hit:
                fired_signals[name] = explain

        priority = Priority.P3
        matched: list[FiredRule] = []
        for level in self.levels:
            groups = level.get("when") or [[]]
            for group in groups:
                if all(signal in fired_signals for signal in group):
                    priority = Priority(level.get("priority", "P3"))
                    matched = [
                        FiredRule(name=signal, explain=fired_signals[signal]) for signal in group
                    ]
                    break
            else:
                continue
            break

        flags: list[str] = []
        for name, spec in self.flag_specs.items():
            hit, _ = _evaluate(spec, context)
            if hit:
                flags.append(name)
        if self._is_stale(finding, stale_days):
            flags.append("stale_snapshot")

        return RuleVerdict(
            priority=priority,
            fired_rules=tuple(matched),
            flags=tuple(flags),
            policy_version=self.policy.version,
            policy_sha256=self.policy.sha256,
        )

    def _is_stale(self, finding: Finding, stale_days: int) -> bool:
        """위협정보 스냅샷이 낡았는지. 낡은 데이터로 판정했다면 그렇게 적는다."""
        today = datetime.now(timezone.utc).date()
        for value in (finding.intel.epss_snapshot_date, finding.intel.kev_snapshot_date):
            if not value:
                continue
            try:
                snapshot = date.fromisoformat(value[:10])
            except ValueError:
                continue
            if (today - snapshot).days > stale_days:
                return True
        return False

    # -- 일괄 판정 --------------------------------------------------------

    def apply(self, findings: tuple[Finding, ...], *, stale_days: int = 7) -> tuple[Finding, ...]:
        """findings에 verdict를 채워 새 튜플을 돌려준다."""
        return tuple(
            Finding(
                installed=f.installed,
                advisory=f.advisory,
                intel=f.intel,
                detection=f.detection,
                fix=f.fix,
                verdict=self.evaluate(f, stale_days=stale_days),
            )
            for f in findings
        )

    # -- 설명 -------------------------------------------------------------

    def describe_level(self, priority: Priority) -> dict[str, Any]:
        for level in self.levels:
            if level.get("priority") == priority.value:
                return level
        return {"priority": priority.value, "label": priority.value}

    def describe_flag(self, name: str) -> dict[str, Any]:
        spec = self.flag_specs.get(name)
        if spec:
            return {"name": name, "label": spec.get("label", name), "note": spec.get("note", "")}
        if name == "stale_snapshot":
            return {
                "name": name,
                "label": "위협정보 스냅샷 오래됨",
                "note": "EPSS/KEV 스냅샷이 기준일보다 오래되었다. 최신 데이터로 재판정이 필요하다",
            }
        return {"name": name, "label": name, "note": ""}


PRIORITY_ORDER = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}


def sort_key(finding: Finding) -> tuple:
    """리포트·UI 정렬용. 우선순위 → CVSS 내림차순 → EPSS 내림차순 → CVE."""
    verdict = finding.verdict
    priority_rank = PRIORITY_ORDER.get(verdict.priority, 9) if verdict else 9
    return (
        priority_rank,
        -(finding.intel.cvss_score or 0.0),
        -(finding.intel.epss or 0.0),
        finding.intel.cve,
    )
