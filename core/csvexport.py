"""결과 표 → CSV.

결재와 공유는 결국 엑셀로 돈다. 화면에서 읽은 것을 그대로 옮길 수 없으면
담당자는 표를 다시 손으로 적게 된다.

**서버에서 만든다.** 48,923건은 브라우저가 들고 있을 양이 아니고, 필터가
서버에서 걸리므로 "화면에 보이는 것"의 정의도 서버에 있다. 청크로 흘려
보내므로 건수와 무관하게 메모리는 일정하다.

**UTF-8 BOM 을 붙인다.** 없으면 Windows 엑셀이 CSV 를 시스템 코드페이지
(한국어 Windows 에서는 CP949)로 읽어 한글이 전부 깨진다. `.ps1` 에서 겪은
것과 같은 문제다.
"""

from __future__ import annotations

from typing import Any, Iterable, Iterator

PRIORITY_LABEL = {
    "P0": "즉시 검토",
    "P1": "우선 검토",
    "P2": "계획 검토",
    "P3": "모니터링",
}

TERNARY_LABEL = {"true": "예", "false": "아니오", "unknown": "미확인"}

BOM = "﻿"


def _percent(value: Any) -> str:
    if value is None:
        return "미확인"
    try:
        percent = float(value) * 100
    except (TypeError, ValueError):
        return "미확인"
    if 0 < percent < 0.01:
        return "<0.01%"
    return f"{percent:.2f}".rstrip("0").rstrip(".") + "%"


COLUMNS: tuple[tuple[str, Any], ...] = (
    ("대응 검토", lambda f: PRIORITY_LABEL.get((f.get("verdict") or {}).get("priority"), "")),
    ("CVE", lambda f: (f.get("intel") or {}).get("cve", "")),
    ("패키지", lambda f: (f.get("installed") or {}).get("name", "")),
    ("패키지 유형", lambda f: (f.get("installed") or {}).get("type", "")),
    ("설치 버전", lambda f: (f.get("installed") or {}).get("version", "")),
    ("수정 버전", lambda f: (f.get("advisory") or {}).get("fixed_version", "")),
    ("수정 상태", lambda f: (f.get("advisory") or {}).get("fix_state", "")),
    ("CVSS", lambda f: (f.get("intel") or {}).get("cvss_score", "")),
    ("심각도", lambda f: (f.get("intel") or {}).get("severity", "")),
    ("악용 예측", lambda f: _percent((f.get("intel") or {}).get("epss"))),
    ("실제 악용(KEV)", lambda f: TERNARY_LABEL.get((f.get("intel") or {}).get("kev"), "미확인")),
    ("공격코드 공개",
     lambda f: TERNARY_LABEL.get((f.get("intel") or {}).get("exploit_available"), "미확인")),
    ("CWE", lambda f: " ".join((f.get("intel") or {}).get("cwe") or ())),
)


def cell(value: Any) -> str:
    """RFC 4180.

    따옴표는 두 번 써서 이스케이프하고, 구분자·따옴표·줄바꿈이 들어 있는 값만
    감싼다. 앞에 `=`·`+`·`-`·`@` 가 오는 값은 엑셀이 **수식으로 해석**하므로
    작은따옴표를 앞세운다 — CVE 설명 같은 외부 문자열이 그대로 들어오는 자리다.
    """
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = f"'{text}"
    return f'"{text.replace(chr(34), chr(34) * 2)}"' if any(c in text for c in ',"\n\r') else text


def rows(findings: Iterable[dict[str, Any]]) -> Iterator[str]:
    """헤더 한 줄 + 항목마다 한 줄. 청크로 흘려 보낼 수 있게 제너레이터다."""
    yield BOM + ",".join(cell(name) for name, _ in COLUMNS) + "\r\n"
    for finding in findings:
        yield ",".join(cell(get(finding)) for _, get in COLUMNS) + "\r\n"


def to_text(findings: Iterable[dict[str, Any]]) -> str:
    """작은 목록용. 큰 것은 `rows()` 를 그대로 흘려 보낸다."""
    return "".join(rows(findings))
