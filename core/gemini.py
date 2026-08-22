"""Google AI Studio (Gemini) 클라이언트.

Argus의 analyzer.py 패턴을 계승한다 — primary/fallback 모델, tenacity 재시도,
JSON 스키마 강제, 레이트리밋 구분.

**전송 직전에 이그레스 가드를 다시 통과시킨다.** 조립 단계에서 이미 검증했지만,
호출부가 facts를 손댔을 가능성을 배제할 수 없다. 여기가 마지막 관문이며,
여기를 통과하지 못하면 네트워크 호출이 일어나지 않는다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .config import Config, get_config
from .prompt import (
    CHAIN_RESPONSE_SCHEMA, RESPONSE_SCHEMA, SYSTEM_INSTRUCTION,
    build_chain_prompt, build_prompt,
)
from .sanitizer import EgressBlocked, EgressGuard


class GeminiError(RuntimeError):
    pass


class GeminiUnavailable(GeminiError):
    """키가 없거나 SDK가 설치되지 않았다. 호출부는 룰 기반으로 물러선다."""


@dataclass
class GeminiResult:
    analyses: list[dict[str, Any]]
    model: str
    attempts: int
    raw_length: int


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """모델 응답에서 JSON을 꺼낸다.

    response_mime_type을 지정해도 마크다운 코드펜스가 섞여 오는 경우가 있어
    세 단계로 물러선다.
    """
    for candidate in (
        text,
        _FENCE_RE.sub("", text).strip(),
    ):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
    match = _OBJECT_RE.search(text or "")
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    raise GeminiError("모델 응답에서 JSON을 읽지 못했습니다.")


class GeminiClient:
    def __init__(self, config: Config | None = None, guard: EgressGuard | None = None,
                 audit: AuditLog | None = None):
        self.config = config or get_config()
        self.guard = guard or EgressGuard.from_config(self.config)
        self.audit = audit or AuditLog(self.config.audit_dir)

    def available(self) -> bool:
        return self.config.ai_ready()

    def _client(self):
        if not self.config.gemini_api_key:
            raise GeminiUnavailable("GEMINI_API_KEY가 설정되지 않았습니다.")
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - 설치 환경에 따라 다름
            raise GeminiUnavailable(
                "google-genai 패키지가 없습니다. pip install -r requirements.txt"
            ) from exc
        return (
            genai.Client(
                api_key=self.config.gemini_api_key,
                http_options=types.HttpOptions(timeout=self.config.gemini_timeout_sec * 1000),
            ),
            types,
        )

    def analyze(self, facts: list[dict[str, Any]], *, scan_id: str = "") -> GeminiResult:
        """VulnFact 목록에 대한 서술을 받아온다.

        전송 전 가드를 통과하지 못하면 EgressBlocked를 던지며, 그 사실도
        감사 로그에 남는다.
        """
        facts = self._guarded(facts, scan_id=scan_id)
        return self._request(
            facts, build_prompt(facts), RESPONSE_SCHEMA, "analyses", scan_id=scan_id
        )

    def analyze_chains(
        self, groups: list[dict[str, Any]], *, scan_id: str = ""
    ) -> GeminiResult:
        """묶음별 연계 분석.

        낮은 등급 여러 건이 서로의 전제를 충족시키면 파급력이 커진다. 그 판단에
        필요한 재료(CVSS 벡터·CWE)는 전부 공개 데이터이므로 이그레스 원칙은
        그대로다 — **같은 가드를 통과한 VulnFact 만** 나간다.

        묶음 식별자는 `group-1` 같은 번호다. "이 자산에 이것들이 함께 설치되어
        있다"는 사실 자체가 내부 정보이므로 패키지명으로 묶음을 부르지 않는다.
        """
        flat = [fact for group in groups for fact in group.get("vulnerabilities", [])]
        self._guarded(flat, scan_id=scan_id)
        return self._request(
            flat, build_chain_prompt(groups), CHAIN_RESPONSE_SCHEMA, "chains", scan_id=scan_id
        )

    def _guarded(self, facts: list[dict[str, Any]], *, scan_id: str) -> list[dict[str, Any]]:
        """마지막 관문. 여기를 통과하지 못한 것은 절대로 나가지 않는다."""
        try:
            return self.guard.enforce(facts)
        except EgressBlocked as blocked:
            self.audit.record(
                action="send", outcome="blocked", facts=facts,
                policy_version=self.guard.policy.version,
                policy_sha256=self.guard.policy.sha256,
                scan_id=scan_id,
                violations=[v.to_dict() for v in blocked.violations],
                error=str(blocked),
            )
            raise

    def _request(
        self,
        facts: list[dict[str, Any]],
        prompt: str,
        schema: dict[str, Any],
        key: str,
        *,
        scan_id: str,
    ) -> GeminiResult:
        client, types = self._client()
        models = [self.config.gemini_model, self.config.gemini_fallback_model]
        attempts = 0
        last_error: Exception | None = None

        for model in [m for m in models if m]:
            for attempt in range(self.config.gemini_max_retries):
                attempts += 1
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=SYSTEM_INSTRUCTION,
                            temperature=0.2,
                            top_p=0.9,
                            response_mime_type="application/json",
                            response_schema=schema,
                        ),
                    )
                    text = getattr(response, "text", "") or ""
                    payload = extract_json(text)
                    analyses = payload.get(key)
                    if not isinstance(analyses, list):
                        raise GeminiError(f"응답에 {key} 배열이 없습니다.")

                    self.audit.record(
                        action="send", outcome="allowed", facts=facts,
                        policy_version=self.guard.policy.version,
                        policy_sha256=self.guard.policy.sha256,
                        scan_id=scan_id, model=model,
                    )
                    return GeminiResult(
                        analyses=analyses, model=model, attempts=attempts, raw_length=len(text)
                    )

                except Exception as exc:  # noqa: BLE001 - SDK 예외 종류가 다양하다
                    last_error = exc
                    message = str(exc).lower()
                    # 일일 쿼터 소진이면 이 모델은 더 시도하지 않고 폴백으로 넘어간다.
                    if "resource_exhausted" in message or "quota" in message or "429" in message:
                        break
                    if attempt == self.config.gemini_max_retries - 1:
                        break
                    import time

                    time.sleep(min(2 ** attempt * 2, 30))

        self.audit.record(
            action="send", outcome="error", facts=facts,
            policy_version=self.guard.policy.version,
            policy_sha256=self.guard.policy.sha256,
            scan_id=scan_id, error=str(last_error),
        )
        raise GeminiError(f"모든 모델에서 실패했습니다: {last_error}")
