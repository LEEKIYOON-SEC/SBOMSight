"""AI 서술 표현 가드.

AI는 우리 환경의 정보를 받지 않으므로 "우리 조직에서 이 취약점의 위험도가
높다"고 판단할 수 없다. 그런데 생성 모델은 관성적으로 단정형 문장을 쓴다.

프롬프트 제약만으로는 부족하므로 생성 후 rules/tone-policy.json 의 패턴으로
다시 점검한다. 걸리면 호출부가 1회 재생성하고, 그래도 위반이면 해당 서술을
버리고 룰 기반 문장으로 되돌린다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import Config, get_config
from .policy import LoadedPolicy, load as load_policy


@dataclass(frozen=True)
class ToneViolation:
    rule: str
    field: str
    reason: str
    sample: str

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "field": self.field, "reason": self.reason, "sample": self.sample}


class ToneGuard:
    def __init__(self, policy: LoadedPolicy):
        self.policy = policy
        self._rules = [
            (spec["name"], re.compile(spec["pattern"], _flags(spec.get("flags", ""))), spec.get("reason", ""))
            for spec in policy.data.get("forbidden") or ()
        ]

    @classmethod
    def from_config(cls, config: Config | None = None) -> "ToneGuard":
        config = config or get_config()
        return cls(load_policy(config.rules_dir / "tone-policy.json"))

    def inspect(self, texts: dict[str, str]) -> list[ToneViolation]:
        """필드명 → 서술 매핑을 검사한다."""
        violations: list[ToneViolation] = []
        for field_name, text in texts.items():
            if not text:
                continue
            for rule, pattern, reason in self._rules:
                match = pattern.search(text)
                if match:
                    violations.append(
                        ToneViolation(rule=rule, field=field_name, reason=reason,
                                      sample=match.group(0).strip()[:60])
                    )
        return violations

    @property
    def preferred(self) -> list[str]:
        return list(self.policy.data.get("preferred_phrasing") or ())


def _flags(spec: str) -> int:
    value = 0
    if "i" in spec:
        value |= re.IGNORECASE
    if "m" in spec:
        value |= re.MULTILINE
    if "s" in spec:
        value |= re.DOTALL
    return value
