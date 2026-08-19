"""AI 프롬프트 조립.

프롬프트에 담기는 것은 **VulnFact 목록뿐**이다. 자산 정보도, 우리 판정도
들어가지 않는다. 그래서 프롬프트 자체를 UI에 그대로 보여 줄 수 있다 —
"AI에게 전송될 내용 전체 보기"가 가능한 이유다.

AI에게 요구하는 것은 설명이지 판단이 아니다. 응답 스키마에 우선순위를 담을
자리를 두지 않으며, 모델이 임의로 넣어도 병합 단계에서 무시한다.
"""

from __future__ import annotations

import json
from typing import Any

# 모델이 지켜야 할 제약. 프롬프트에 실리고, 생성 후 core/tone.py 가 다시 점검한다.
SYSTEM_INSTRUCTION = """\
당신은 공개된 취약점 데이터를 근거로 보안 담당자가 읽을 설명을 작성합니다.

[당신이 받는 것]
공개 취약점 데이터만 받습니다: CVE ID, CVSS 점수와 벡터, CWE, EPSS,
CISA KEV 등재 여부, 공개 exploit 존재 여부와 출처, 공개 advisory가 지목한
패키지명과 영향 버전범위, 수정 버전, OS 계열.

[당신이 받지 못하는 것]
요청자의 자산 정보는 일절 포함되어 있지 않습니다. 어떤 서버에 무엇이 설치되어
있는지, 실제 설치 버전이 무엇인지, 몇 대나 영향을 받는지, 내부적으로 어떤
대응 우선순위가 매겨졌는지 알 수 없습니다.

[따라서 지켜야 할 것]
1. 요청자의 조직이나 자산을 지칭하지 마십시오. "귀사", "우리 조직", "해당 서버",
   "사내" 같은 표현을 쓰지 마십시오.
2. 특정 환경의 위험도를 단정하지 마십시오. "매우 위험합니다", "치명적입니다"가
   아니라 "공개 데이터를 기준으로 ~한 특성이 관측됩니다"라고 쓰십시오.
3. 최종 조치 여부를 명령하지 마십시오. "반드시 패치해야 합니다"가 아니라
   "우선적인 대응을 검토할 필요가 있습니다", "높은 우선순위로 조치하는 것을
   권고합니다"라고 쓰십시오.
4. 대응 우선순위 등급(P0~P3)을 말하지 마십시오. 등급은 요청자 측 정책 룰이
   결정하며 당신은 그 결과를 알지 못합니다.
5. 패치 명령어(dnf, apt, npm, pip 등)를 작성하지 마십시오. 실행 절차는 요청자
   측에서 결정론적으로 생성합니다.
6. 주어진 데이터에 없는 사실을 지어내지 마십시오. 모르는 것은 "공개된 정보만으로는
   확인되지 않습니다"라고 쓰십시오. 특히 CVSS 벡터나 CWE가 비어 있으면 그것을
   근거로 한 서술을 하지 마십시오.

[작성 언어]
한국어. 보안 담당자가 결재 문서에 그대로 옮길 수 있는 문어체로 씁니다.
"""

# 응답 스키마. priority 를 담을 자리가 없다는 것이 핵심이다.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "analyses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cve": {"type": "string"},
                    "technical_risk": {
                        "type": "string",
                        "description": "이 취약점이 어떤 공격을 가능하게 하는지, 어떤 조건에서 성립하는지. 3~5문장.",
                    },
                    "attack_preconditions": {
                        "type": "array", "items": {"type": "string"},
                        "description": "공격이 성립하기 위한 조건. CVSS 벡터에서 읽히는 것만.",
                    },
                    "impact_types": {
                        "type": "array", "items": {"type": "string"},
                        "description": "공격 성공 시 나타날 수 있는 영향 유형 (RCE, 권한 상승, DoS, 정보 노출 등).",
                    },
                    "exploitability_note": {
                        "type": "string",
                        "description": "EPSS·KEV·공개 exploit을 종합한 악용 가능성 서술. 2~4문장.",
                    },
                    "response_rationale": {
                        "type": "string",
                        "description": "왜 대응을 검토해야 하는지의 근거. 등급을 말하지 말고 근거만 제시. 3~5문장.",
                    },
                    "recommendation_note": {
                        "type": "string",
                        "description": "패치 시 유의할 점이나 임시 완화 방향. 명령어는 쓰지 않는다. 2~3문장.",
                    },
                },
                "required": ["cve", "technical_risk", "exploitability_note", "response_rationale"],
            },
        }
    },
    "required": ["analyses"],
}

NARRATIVE_FIELDS = (
    "technical_risk",
    "exploitability_note",
    "response_rationale",
    "recommendation_note",
)


def build_prompt(facts: list[dict[str, Any]]) -> str:
    """VulnFact 목록으로 사용자 프롬프트를 만든다.

    facts 외의 어떤 것도 들어가지 않는다. 이 문자열 전체를 UI에 그대로
    보여 줄 수 있어야 하며, 그것이 이 함수의 계약이다.
    """
    payload = json.dumps({"vulnerabilities": facts}, ensure_ascii=False, indent=2)
    return f"""\
아래는 공개 취약점 데이터입니다. 각 항목에 대해 지정된 스키마로 분석을 작성하십시오.

값이 "unknown"이거나 null인 항목은 **확인되지 않은 것**이지 "없음"이 아닙니다.
예를 들어 exploit_available이 "unknown"이면 "공개 exploit이 없다"가 아니라
"공개 exploit 존재 여부가 확인되지 않았다"입니다. 이 구분을 서술에 반영하십시오.

affected_version_range와 fixed_version은 공개 advisory가 공표한 값이며,
요청자의 실제 설치 버전이 아닙니다.

{payload}

각 CVE에 대해 하나의 분석 객체를 만들고, cve 필드에 위 데이터의 cve 값을
그대로 넣으십시오.
"""


def build_full_text(facts: list[dict[str, Any]]) -> str:
    """UI의 "AI에게 전송될 내용 전체 보기"에 그대로 실리는 문자열."""
    return f"=== 시스템 지시 ===\n{SYSTEM_INSTRUCTION}\n\n=== 요청 ===\n{build_prompt(facts)}"
