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


# ---------------------------------------------------------------------------
# 연계 분석 — 낮은 등급 여러 건이 엮이면 파급력이 커진다
# ---------------------------------------------------------------------------

CHAIN_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "chains": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "group": {
                        "type": "string",
                        "description": "요청에 실린 group 식별자를 그대로 옮긴다.",
                    },
                    "analysis": {
                        "type": "string",
                        "description": (
                            "이 묶음의 취약점들이 서로의 전제를 충족시켜 연쇄될 수 있는지, "
                            "CVSS 벡터와 CWE 로 읽히는 근거만으로 서술. 연쇄 가능성이 "
                            "보이지 않으면 그렇게 쓴다. 4~6문장."
                        ),
                    },
                },
                "required": ["group", "analysis"],
            },
        }
    },
    "required": ["chains"],
}


def build_chain_prompt(groups: list[dict[str, Any]]) -> str:
    """묶음별 연계 분석 요청.

    **전달되는 것은 VulnFact 뿐이다.** 묶음 식별자도 패키지명이 아니라
    `group-1` 같은 번호다 — advisory 가 지목한 패키지명은 이미 VulnFact 안에
    공개 데이터로 들어 있지만, "이 자산에 이것들이 함께 설치되어 있다"는 사실
    자체는 내부 정보이므로 묶음을 우리 자산과 연결 짓지 않는다.

    이 함수의 계약은 build_prompt 와 같다: 반환 문자열 전체를 화면에 그대로
    보여 줄 수 있어야 한다.
    """
    payload = json.dumps({"groups": groups}, ensure_ascii=False, indent=2)
    return f"""\
아래는 공개 취약점 데이터를 묶음별로 정리한 것입니다. 각 묶음에 대해 **취약점들이
서로 연쇄될 수 있는지**를 분석하십시오.

낮은 심각도의 취약점도 서로의 전제를 충족시키면 파급력이 커집니다. 예를 들어
`PR:N` 이면서 정보 노출(`C:H`)에 그치는 취약점이, `PR:L` 을 요구하는 다른
취약점의 전제를 충족시킬 수 있습니다.

지켜야 할 것:

- CVSS 벡터(AV/AC/PR/UI/S/C/I/A)와 CWE 로 **읽히는 근거만** 쓰십시오.
  벡터가 비어 있는 항목은 연쇄 논리의 근거로 삼지 마십시오.
- 연쇄 가능성이 보이지 않으면 "제시된 데이터로는 연쇄 가능성이 확인되지
  않습니다"라고 쓰십시오. 억지로 엮지 마십시오.
- **공개 데이터 기준의 기술적 가능성**을 쓰는 것이며, 특정 환경에서 실제로
  성립하는지는 알 수 없습니다. 단정하지 마십시오.
- 묶음이 어느 자산의 것인지, 실제로 설치되어 있는지는 알 수 없습니다.

{payload}

각 묶음에 대해 하나의 분석 객체를 만들고, group 필드에 위 데이터의 group 값을
그대로 넣으십시오.
"""


def build_chain_full_text(groups: list[dict[str, Any]]) -> str:
    """연계 분석에서 "전송될 내용 전체 보기"에 실리는 문자열."""
    return f"=== 시스템 지시 ===\n{SYSTEM_INSTRUCTION}\n\n=== 요청 ===\n{build_chain_prompt(groups)}"


# ---------------------------------------------------------------------------
# 연계 상승 — **패키지를 가로질러** 묻는다
# ---------------------------------------------------------------------------
#
# 앞의 `build_chain_prompt` 는 한 패키지 안의 CVE 들끼리 엮이는지를 물었다.
# 그런데 같은 라이브러리의 버그 여섯 건은 서로 무관하고 조치도 하나다 — 엮을
# 것이 없다. 실제로 등급이 뛰는 조합은 패키지를 가로지른다:
#
#     정보 노출(PR:N, C:H)  →  권한 상승(PR:L, C:H/I:H/A:H)
#
# 앞의 것이 뒤의 것이 요구하는 자격을 만들어 준다. 그래서 여기서는 발판 후보와
# 상승 후보를 **함께** 싣고, 그 사이의 연쇄를 묻는다.

ESCALATION_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "chains": {
            "type": "array",
            "description": "성립 가능한 연쇄. 억지로 만들지 말고, 없으면 빈 배열.",
            "items": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "이 연쇄를 한 줄로. 예: '인증 없는 정보 노출로 얻은 자격을 통한 권한 상승'",
                    },
                    "steps": {
                        "type": "array",
                        "description": "연쇄의 각 단계. 2~4단계.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "cve": {"type": "string", "description": "요청 데이터에 있는 cve 값 그대로."},
                                "role": {
                                    "type": "string",
                                    "description": "이 단계가 하는 일. 예: '초기 진입', '자격 획득', '권한 상승', '영향 확대'",
                                },
                                "why": {
                                    "type": "string",
                                    "description": "왜 이 단계가 다음 단계의 전제를 충족시키는지. CVSS 벡터와 CWE 로 읽히는 근거만. 1~2문장.",
                                },
                            },
                            "required": ["cve", "role", "why"],
                        },
                    },
                    "outcome": {
                        "type": "string",
                        "description": "연쇄가 성립했을 때 도달하는 상태. 2~3문장.",
                    },
                    "escalation": {
                        "type": "string",
                        "description": (
                            "단독으로 볼 때와 이어서 볼 때 무엇이 달라지는지. "
                            "'각각은 자격을 요구하거나 정보 노출에 그치지만, 이어지면 …' 형태로. 2~3문장."
                        ),
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["높음", "보통", "낮음"],
                        "description": "공개 데이터만으로 이 연쇄를 얼마나 확신할 수 있는지.",
                    },
                    "confidence_reason": {
                        "type": "string",
                        "description": "그 확신도의 근거. 벡터가 비어 있거나 CWE 가 없으면 그렇게 쓴다. 1~2문장.",
                    },
                },
                "required": ["title", "steps", "outcome", "escalation", "confidence"],
            },
        },
        "note": {
            "type": "string",
            "description": "연쇄가 하나도 보이지 않으면 그 이유. 보이면 전체에 대한 한 줄 총평.",
        },
    },
    "required": ["chains", "note"],
}


def build_escalation_prompt(
    footholds: list[dict[str, Any]], escalations: list[dict[str, Any]]
) -> str:
    """연계 상승 요청.

    전달되는 것은 두 갈래의 VulnFact 뿐이다. 어느 자산의 것인지, 실제로 함께
    설치되어 있는지는 싣지 않는다 — 그것이 이 도구의 이그레스 원칙이고,
    이 함수의 반환값 전체를 화면에 그대로 보여 줄 수 있어야 한다.
    """
    payload = json.dumps(
        {"footholds": footholds, "escalations": escalations}, ensure_ascii=False, indent=2
    )
    return f"""\
아래는 공개 취약점 데이터를 두 갈래로 나눈 것입니다.

- `footholds` — 자격 없이 성립하는 취약점(PR:N)들입니다. 성공하면 정보 노출,
  무결성 훼손, 또는 범위 변경이 일어납니다.
- `escalations` — 자격을 요구하지만(PR:L 또는 PR:H) 성공하면 기밀성·무결성·
  가용성에 큰 영향을 주는 취약점들입니다.

**묻는 것은 하나입니다: 앞의 것이 뒤의 것의 전제를 충족시켜 연쇄될 수 있는가.**

단독으로 보면 중간 등급인 취약점도, 하나가 다른 하나가 요구하는 자격을 만들어
주면 결과적으로 훨씬 큰 영향에 도달합니다. 그 관계가 보이는 조합을 찾아
서술하십시오.

지켜야 할 것:

- CVSS 벡터(AV/AC/PR/UI/S/C/I/A)와 CWE 로 **읽히는 근거만** 쓰십시오.
  벡터가 비어 있는 항목은 연쇄 논리의 근거로 삼지 마십시오.
- 단계마다 **왜 그 단계가 다음 단계의 전제를 충족시키는지**를 적으십시오.
  "둘 다 심각하다"는 연쇄 논리가 아닙니다.
- 억지로 엮지 마십시오. 성립하는 조합이 없으면 `chains` 를 빈 배열로 두고
  `note` 에 그 이유를 쓰십시오. 빈 결과도 유효한 답입니다.
- 같은 두 CVE 로 만들 수 있는 연쇄는 하나만 쓰십시오.
- 이 데이터가 어느 환경의 것인지, 실제로 함께 존재하는지는 알 수 없습니다.
  **공개 데이터 기준의 기술적 가능성**을 쓰는 것이며 단정하지 마십시오.

{payload}

cve 필드에는 위 데이터의 cve 값을 그대로 넣으십시오. 위 데이터에 없는 CVE 를
연쇄에 넣지 마십시오.
"""


def build_escalation_full_text(
    footholds: list[dict[str, Any]], escalations: list[dict[str, Any]]
) -> str:
    """연계 상승에서 "전송될 내용 전체 보기"에 실리는 문자열."""
    return (
        f"=== 시스템 지시 ===\n{SYSTEM_INSTRUCTION}\n\n"
        f"=== 요청 ===\n{build_escalation_prompt(footholds, escalations)}"
    )
