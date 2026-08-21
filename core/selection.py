"""탐지 결과 중 일부만 골라내기.

담당자가 표에서 체크한 항목만 AI로 보내고, 그 항목만으로 보고서를 만든다.
"전부 보내고 나중에 거른다"가 아니라 **고른 것만 조립한다**는 순서가 중요하다 —
이그레스 미리보기에 보이는 것과 실제로 나가는 것이 같아야 하기 때문이다.

선택 키는 `Finding.key`(= `CVE|패키지명|설치버전|purl`)를 그대로 쓴다. 이 문자열은
내부 정보이므로 **브라우저와 서버 사이에서만 오간다.** AI로 나가는 VulnFact는
core/vulnfact.py 가 공개 계층에서 따로 조립하며, 선택 키는 그 경로에 등장하지
않는다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class Selection:
    """선택 적용 결과."""

    findings: tuple[Finding, ...]
    requested: tuple[str, ...]
    unknown: tuple[str, ...]
    """요청받았지만 이 스캔에 없는 키. 조용히 무시하지 않고 호출부에 알린다."""

    @property
    def is_all(self) -> bool:
        return not self.requested

    def to_dict(self) -> dict[str, object]:
        return {
            "selected": len(self.findings),
            "requested": len(self.requested),
            "unknown": list(self.unknown),
            "scope": "all" if self.is_all else "selection",
        }


def apply(findings: tuple[Finding, ...] | list[Finding], keys: list[str] | None) -> Selection:
    """선택 키 목록으로 findings를 추린다.

    키가 비어 있으면 **전체**를 뜻한다. 빈 선택을 '아무것도 아님'으로 해석하면
    링크로 들어온 보고서가 빈 문서가 되어 버린다.

    같은 키가 여러 번 와도 결과는 한 번만 담는다. 순서는 원본 순서를 지킨다 —
    보고서 정렬은 상위 단계(report.py)의 몫이고, 여기서 순서를 바꾸면
    미리보기와 보고서의 항목 순서가 어긋난다.
    """
    requested = tuple(dict.fromkeys(keys or ()))
    if not requested:
        return Selection(findings=tuple(findings), requested=(), unknown=())

    wanted = set(requested)
    picked = tuple(f for f in findings if f.key in wanted)
    found = {f.key for f in picked}
    unknown = tuple(k for k in requested if k not in found)
    return Selection(findings=picked, requested=requested, unknown=unknown)
