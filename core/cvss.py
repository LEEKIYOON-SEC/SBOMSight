"""CVSS 벡터와 CWE를 사람이 읽는 사실로 옮긴다.

이 모듈은 **해석이 아니라 번역**이다. "AV:N/AC:L/PR:N/UI:N"이라는 표기가
"네트워크를 통해, 특별한 조건 없이, 권한 없이, 사용자 조작 없이"라는 뜻임을
풀어 쓸 뿐 새로운 판단을 더하지 않는다.

덕분에 AI가 없어도 리포트의 ②기술적 위험성 절이 채워진다. AI가 붙으면
같은 자리에 더 읽기 좋은 서술이 얹히고, 이 룰 기반 문장은 폴백으로 남는다.

표현 원칙: 우리 환경에 대해 단정하지 않는다. "이 취약점은 원격에서 인증 없이
악용될 수 있는 형태"라고는 쓰되 "귀사의 서버가 위험하다"고 쓰지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_VECTOR_RE = re.compile(r"([A-Z]+):([A-Z]+)")

# --- CVSS 3.x -------------------------------------------------------------

_AV = {"N": "네트워크", "A": "인접 네트워크", "L": "로컬", "P": "물리적 접근"}
_AC = {"L": "낮음", "H": "높음"}
_PR = {"N": "불필요", "L": "일반 사용자 권한 필요", "H": "관리자 권한 필요"}
_UI = {"N": "불필요", "R": "사용자 조작 필요", "P": "수동적 사용자 조작 필요", "A": "능동적 사용자 조작 필요"}
_SCOPE = {"U": "변경 없음", "C": "변경됨 (다른 구성요소로 영향 확산)"}
_IMPACT = {"H": "높음", "L": "낮음", "N": "없음"}

# --- CWE 유형 -------------------------------------------------------------

_CWE_LABELS = {
    "CWE-22": "경로 탐색 (Path Traversal)",
    "CWE-77": "명령어 삽입 (Command Injection)",
    "CWE-78": "OS 명령어 삽입 (OS Command Injection)",
    "CWE-79": "크로스사이트 스크립팅 (XSS)",
    "CWE-89": "SQL 삽입 (SQL Injection)",
    "CWE-94": "코드 삽입 (Code Injection)",
    "CWE-119": "메모리 버퍼 경계 위반",
    "CWE-120": "버퍼 오버플로",
    "CWE-125": "범위 밖 읽기 (Out-of-bounds Read)",
    "CWE-190": "정수 오버플로",
    "CWE-200": "민감 정보 노출",
    "CWE-269": "부적절한 권한 관리",
    "CWE-287": "부적절한 인증",
    "CWE-295": "부적절한 인증서 검증",
    "CWE-306": "중요 기능에 대한 인증 누락",
    "CWE-352": "크로스사이트 요청 위조 (CSRF)",
    "CWE-362": "경쟁 조건 (Race Condition)",
    "CWE-400": "자원 소모 제어 실패",
    "CWE-401": "메모리 누수",
    "CWE-416": "해제 후 사용 (Use-After-Free)",
    "CWE-434": "위험한 형식의 파일 업로드 제한 없음",
    "CWE-476": "NULL 포인터 역참조",
    "CWE-502": "신뢰할 수 없는 데이터 역직렬화",
    "CWE-506": "악성 코드 삽입 (Embedded Malicious Code)",
    "CWE-611": "XML 외부 개체 참조 (XXE)",
    "CWE-770": "제한 없는 자원 할당",
    "CWE-787": "범위 밖 쓰기 (Out-of-bounds Write)",
    "CWE-798": "하드코딩된 자격증명",
    "CWE-863": "부적절한 인가",
    "CWE-918": "서버 측 요청 위조 (SSRF)",
    "CWE-1321": "프로토타입 오염",
}

# 메모리 안전성 계열 — 원격 코드 실행으로 이어질 소지가 있는 유형
_MEMORY_SAFETY = {"CWE-119", "CWE-120", "CWE-125", "CWE-416", "CWE-476", "CWE-787", "CWE-190"}
_DOS_ORIENTED = {"CWE-400", "CWE-401", "CWE-770", "CWE-476"}


@dataclass(frozen=True)
class CvssFacts:
    """CVSS 벡터를 풀어 쓴 사실들. 값이 없으면 빈 문자열/빈 목록이다."""

    version: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""
    preconditions: tuple[str, ...] = ()
    impacts: tuple[str, ...] = ()
    remote_unauthenticated: bool = False

    @property
    def parsed(self) -> bool:
        return bool(self.attack_vector)


def parse_vector(vector: str) -> dict[str, str]:
    """CVSS 벡터 문자열을 메트릭 딕셔너리로 옮긴다."""
    if not vector:
        return {}
    metrics = dict(_VECTOR_RE.findall(vector.upper()))
    metrics.pop("CVSS", None)
    return metrics


def describe(vector: str) -> CvssFacts:
    """CVSS 벡터에서 공격 조건과 영향을 뽑는다. v3.x와 v4.0을 모두 받는다."""
    metrics = parse_vector(vector)
    if not metrics:
        return CvssFacts()

    version = "4.0" if "VC" in metrics or "AT" in metrics else "3.x"

    # v4.0은 영향 메트릭 이름이 다르다 (VC/VI/VA = Vulnerable system).
    conf = metrics.get("C") or metrics.get("VC") or ""
    integ = metrics.get("I") or metrics.get("VI") or ""
    avail = metrics.get("A") or metrics.get("VA") or ""

    av = metrics.get("AV", "")
    ac = metrics.get("AC", "")
    pr = metrics.get("PR", "")
    ui = metrics.get("UI", "")

    preconditions: list[str] = []
    if av:
        preconditions.append(f"공격 경로: {_AV.get(av, av)}")
    if ac:
        preconditions.append(f"공격 난이도: {_AC.get(ac, ac)}")
    if "AT" in metrics:   # v4.0 Attack Requirements
        preconditions.append(
            "추가 공격 조건: " + ("불필요" if metrics["AT"] == "N" else "필요")
        )
    if pr:
        preconditions.append(f"필요 권한: {_PR.get(pr, pr)}")
    if ui:
        preconditions.append(f"사용자 상호작용: {_UI.get(ui, ui)}")
    if metrics.get("S"):
        preconditions.append(f"영향 범위(Scope): {_SCOPE.get(metrics['S'], metrics['S'])}")

    impacts: list[str] = []
    if conf and conf != "N":
        impacts.append(f"기밀성 영향 {_IMPACT.get(conf, conf)} — 정보 노출 가능성")
    if integ and integ != "N":
        impacts.append(f"무결성 영향 {_IMPACT.get(integ, integ)} — 데이터 변조 가능성")
    if avail and avail != "N":
        impacts.append(f"가용성 영향 {_IMPACT.get(avail, avail)} — 서비스 중단 가능성")

    return CvssFacts(
        version=version,
        attack_vector=_AV.get(av, av),
        attack_complexity=_AC.get(ac, ac),
        privileges_required=_PR.get(pr, pr),
        user_interaction=_UI.get(ui, ui),
        scope=_SCOPE.get(metrics.get("S", ""), ""),
        confidentiality=_IMPACT.get(conf, conf),
        integrity=_IMPACT.get(integ, integ),
        availability=_IMPACT.get(avail, avail),
        preconditions=tuple(preconditions),
        impacts=tuple(impacts),
        remote_unauthenticated=(av == "N" and pr == "N" and ui == "N"),
    )


def cwe_label(cwe: str) -> str:
    """CWE 번호에 한국어 유형명을 붙인다. 모르는 번호는 번호만 돌려준다."""
    return f"{cwe} {_CWE_LABELS[cwe]}" if cwe in _CWE_LABELS else cwe


def classify_impact(vector: str, cwes: tuple[str, ...] = ()) -> tuple[str, ...]:
    """공격 성공 시 나타날 수 있는 영향 유형을 분류한다.

    CVSS 영향 메트릭과 CWE 유형을 조합한 **가능성 분류**이지 단정이 아니다.
    실제 영향은 해당 구성요소가 어떻게 쓰이는지에 달려 있으며, 그 판단은
    담당자의 몫이다.
    """
    facts = describe(vector)
    cwe_set = {c.upper() for c in cwes}
    labels: list[str] = []

    high_all = facts.confidentiality == "높음" and facts.integrity == "높음" and facts.availability == "높음"
    memory_issue = bool(cwe_set & _MEMORY_SAFETY)
    injection = bool(cwe_set & {"CWE-77", "CWE-78", "CWE-94", "CWE-502", "CWE-1321"})

    if (high_all and facts.remote_unauthenticated) or (memory_issue and facts.attack_vector == "네트워크") or injection:
        labels.append("원격 코드 실행 (RCE) 가능성")
    if facts.integrity in ("높음", "낮음") and cwe_set & {"CWE-269", "CWE-863", "CWE-287", "CWE-306", "CWE-798"}:
        labels.append("권한 상승 · 인가 우회 가능성")
    if facts.availability == "높음" or cwe_set & _DOS_ORIENTED:
        labels.append("서비스 거부 (DoS) 가능성")
    if facts.confidentiality in ("높음", "낮음") or cwe_set & {"CWE-200", "CWE-125", "CWE-22", "CWE-918", "CWE-611"}:
        labels.append("정보 노출 가능성")
    if facts.integrity in ("높음", "낮음") and not any(l.startswith("원격 코드") for l in labels):
        labels.append("데이터 변조 가능성")

    # 중복 제거하되 순서는 유지한다 (심각한 것부터 읽히도록).
    return tuple(dict.fromkeys(labels))
