"""이그레스 가드 — 조립된 VulnFact를 policy/egress-policy.json 에 대고 검증한다.

3중 검증이며, 하나라도 걸리면 **전송을 중단한다(fail-closed)**:

  1. 스키마 검증 — 모든 키가 허용 목록에 있는가, 금칙 필드명이 아닌가
  2. 값 검증   — 타입·범위·enum·정규식·길이를 통과하는가
  3. 금칙 패턴 — IP·경로·이메일·MAC·UUID·내부 도메인·한글·자격증명 흔적이 없는가

같은 정책 파일을 web/js/core/sanitizer.js 도 읽으며,
policy/egress-test-vectors.json 으로 두 구현의 동치성을 검증한다.

이 가드는 2차 방어다. 1차 방어는 core/vulnfact.py 의 함수 시그니처가
로컬 계층을 아예 받지 않는다는 사실이다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config, get_config
from .policy import LoadedPolicy, load as load_policy


def _flags(spec: str) -> int:
    """정책의 flags 문자열을 re 플래그로 옮긴다. JS의 RegExp 플래그와 같은 표기."""
    value = 0
    if "i" in spec:
        value |= re.IGNORECASE
    if "m" in spec:
        value |= re.MULTILINE
    if "s" in spec:
        value |= re.DOTALL
    return value


class EgressBlocked(Exception):
    """검증 실패로 전송이 중단되었다. 어떤 규칙에 왜 걸렸는지를 담는다."""

    def __init__(self, violations: list["Violation"]):
        self.violations = violations
        super().__init__(
            "외부 전송이 차단되었습니다 ("
            + "; ".join(f"{v.rule}@{v.path}: {v.reason}" for v in violations[:5])
            + (f" 외 {len(violations) - 5}건" if len(violations) > 5 else "")
            + ")"
        )


@dataclass(frozen=True)
class Violation:
    rule: str            # forbidden_field / unknown_field / type / pattern / range / forbidden_pattern
    path: str            # facts[0].cvss_vector 처럼 어디서 걸렸는지
    reason: str
    sample: str = ""     # 걸린 값의 일부. 로그로 남으므로 짧게 자른다.

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "path": self.path, "reason": self.reason, "sample": self.sample}


@dataclass
class SanitizeResult:
    ok: bool
    facts: list[dict[str, Any]] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    policy_version: str = ""
    policy_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "facts": self.facts,
            "violations": [v.to_dict() for v in self.violations],
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
        }


class EgressGuard:
    def __init__(self, policy: LoadedPolicy):
        self.policy = policy
        data = policy.data
        self.allowed: dict[str, Any] = data.get("allowed_fields") or {}
        self.forbidden_names: set[str] = {n.lower() for n in data.get("forbidden_field_names") or ()}
        self.limits: dict[str, Any] = data.get("limits") or {}
        # 정규식 플래그는 정책에 명시한다. (?i) 같은 인라인 플래그는 JavaScript가
        # 컴파일하지 못해 두 구현이 갈리므로 쓰지 않는다.
        self._patterns = [
            (spec["name"], re.compile(spec["pattern"], _flags(spec.get("flags", ""))), spec.get("reason", ""))
            for spec in data.get("forbidden_patterns") or ()
        ]
        self._field_re: dict[str, re.Pattern] = {}

    @classmethod
    def from_config(cls, config: Config | None = None) -> "EgressGuard":
        config = config or get_config()
        return cls(load_policy(config.policy_dir / "egress-policy.json"))

    # -- 정규식 캐시 -------------------------------------------------------

    def _compiled(self, pattern: str) -> re.Pattern:
        if pattern not in self._field_re:
            self._field_re[pattern] = re.compile(pattern)
        return self._field_re[pattern]

    # -- 1·2단계: 스키마와 값 ------------------------------------------------

    def _check_scalar(self, spec: dict[str, Any], value: Any, path: str) -> list[Violation]:
        out: list[Violation] = []
        expected = spec.get("type", "string")

        if value is None:
            if not spec.get("nullable"):
                out.append(Violation("type", path, "값이 없는데 nullable이 아님"))
            return out

        if expected == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                out.append(Violation("type", path, f"number가 아님 ({type(value).__name__})"))
                return out
            if "min" in spec and value < spec["min"]:
                out.append(Violation("range", path, f"{value} < 최솟값 {spec['min']}"))
            if "max" in spec and value > spec["max"]:
                out.append(Violation("range", path, f"{value} > 최댓값 {spec['max']}"))
            return out

        if not isinstance(value, str):
            out.append(Violation("type", path, f"string이 아님 ({type(value).__name__})"))
            return out

        if "max_length" in spec and len(value) > spec["max_length"]:
            out.append(Violation("range", path, f"길이 {len(value)} > {spec['max_length']}"))
        if "enum" in spec and value not in spec["enum"]:
            out.append(Violation("pattern", path, f"허용 값이 아님: {value[:40]!r}", value[:40]))
        if "pattern" in spec and not self._compiled(spec["pattern"]).match(value):
            out.append(
                Violation("pattern", path, f"형식 불일치: {spec['pattern']}", value[:60])
            )
        return out

    def _check_field(self, name: str, spec: dict[str, Any], value: Any, path: str) -> list[Violation]:
        expected = spec.get("type", "string")

        if expected == "array":
            if not isinstance(value, list):
                return [Violation("type", path, f"array가 아님 ({type(value).__name__})")]
            out: list[Violation] = []
            if "max_items" in spec and len(value) > spec["max_items"]:
                out.append(Violation("range", path, f"항목 {len(value)} > {spec['max_items']}"))
            item_spec = spec.get("items") or {}
            for index, item in enumerate(value):
                item_path = f"{path}[{index}]"
                if item_spec.get("type") == "object":
                    out.extend(self._check_object(item_spec, item, item_path))
                else:
                    out.extend(self._check_scalar(item_spec, item, item_path))
            return out

        return self._check_scalar(spec, value, path)

    def _check_object(self, spec: dict[str, Any], value: Any, path: str) -> list[Violation]:
        if not isinstance(value, dict):
            return [Violation("type", path, f"object가 아님 ({type(value).__name__})")]
        fields = spec.get("fields") or {}
        out: list[Violation] = []
        for key in value:
            if key.lower() in self.forbidden_names:
                out.append(Violation("forbidden_field", f"{path}.{key}", "금칙 필드명"))
            elif key not in fields:
                out.append(Violation("unknown_field", f"{path}.{key}", "허용 목록에 없는 키"))
        for key, field_spec in fields.items():
            if key in value:
                out.extend(self._check_scalar(field_spec, value[key], f"{path}.{key}"))
        return out

    def _check_schema(self, fact: dict[str, Any], path: str) -> list[Violation]:
        out: list[Violation] = []
        if not isinstance(fact, dict):
            return [Violation("type", path, "VulnFact가 object가 아님")]

        for key in fact:
            if key.lower() in self.forbidden_names:
                # 조립기가 넣을 수 없는 이름이다. 여기 걸렸다면 설계가 어긋난 것이다.
                out.append(Violation("forbidden_field", f"{path}.{key}", "금칙 필드명 — 내부 정보일 수 있음"))
            elif key not in self.allowed:
                out.append(Violation("unknown_field", f"{path}.{key}", "허용 목록에 없는 키"))

        for key, spec in self.allowed.items():
            if key not in fact:
                if spec.get("required"):
                    out.append(Violation("type", f"{path}.{key}", "필수 필드 누락"))
                continue
            out.extend(self._check_field(key, spec, fact[key], f"{path}.{key}"))
        return out

    # -- 3단계: 금칙 패턴 ---------------------------------------------------

    def _walk_strings(self, node: Any, path: str):
        if isinstance(node, str):
            yield path, node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield from self._walk_strings(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                yield from self._walk_strings(value, f"{path}[{index}]")

    def _check_patterns(self, fact: Any, path: str) -> list[Violation]:
        out: list[Violation] = []
        for value_path, text in self._walk_strings(fact, path):
            for name, pattern, reason in self._patterns:
                match = pattern.search(text)
                if match:
                    out.append(
                        Violation("forbidden_pattern", value_path, f"{name}: {reason}", match.group(0)[:60])
                    )
        return out

    # -- 공개 진입점 --------------------------------------------------------

    def check(self, facts: list[dict[str, Any]]) -> SanitizeResult:
        """검증만 하고 결과를 돌려준다. 예외를 던지지 않는다 (미리보기용)."""
        violations: list[Violation] = []

        max_facts = self.limits.get("max_facts_per_request")
        if max_facts and len(facts) > max_facts:
            violations.append(
                Violation("range", "facts", f"한 요청 최대 {max_facts}건인데 {len(facts)}건")
            )

        for index, fact in enumerate(facts):
            path = f"facts[{index}]"
            violations.extend(self._check_schema(fact, path))
            violations.extend(self._check_patterns(fact, path))

        max_bytes = self.limits.get("max_payload_bytes")
        if max_bytes:
            size = len(json.dumps(facts, ensure_ascii=False).encode("utf-8"))
            if size > max_bytes:
                violations.append(Violation("range", "facts", f"크기 {size}B > 한도 {max_bytes}B"))

        return SanitizeResult(
            ok=not violations,
            facts=facts,
            violations=violations,
            policy_version=self.policy.version,
            policy_sha256=self.policy.sha256,
        )

    def enforce(self, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """검증에 실패하면 EgressBlocked를 던진다. 실제 전송 직전에 쓴다.

        '문제가 있는 항목만 빼고 나머지는 보낸다'를 하지 않는 이유: 무엇이
        어떻게 새려 했는지 모르는 상태에서 나머지가 안전하다고 볼 근거가 없다.
        """
        result = self.check(facts)
        if not result.ok:
            raise EgressBlocked(result.violations)
        return result.facts
