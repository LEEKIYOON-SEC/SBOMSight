"""탐지 결과의 조회 — 정렬·필터·페이징.

Rocky 9 서버 한 대가 수백~수천 건을 낸다. 지금까지는 findings 전체를 JSON으로
내려보내고 브라우저가 전부 DOM에 그렸는데, 그 방식은 자산이 늘수록 무너진다.
자르고 정렬하는 일을 서버에서 한다.

**미확인 값은 방향과 무관하게 항상 뒤로 보낸다.** CVSS나 EPSS가 없는 것은
"낮다"가 아니라 "모른다"이다. 내림차순에서 맨 뒤로 보내는 것은 자연스럽지만
오름차순에서 맨 앞에 세우면 "가장 안전한 것"처럼 읽힌다 — 그것은 거짓말이다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .models import Finding, Priority

# 정렬 키 → finding에서 값을 꺼내는 함수. None을 돌려주면 "미확인"이다.
_SORTERS: dict[str, Callable[[Finding], Any]] = {
    "priority": lambda f: _PRIORITY_ORDER.get(f.verdict.priority, 99) if f.verdict else None,
    "cvss": lambda f: f.intel.cvss_score,
    "epss": lambda f: f.intel.epss,
    "package": lambda f: (f.installed.name or "").lower(),
    "cve": lambda f: f.intel.cve,
    "fixed": lambda f: (f.advisory.fixed_version or "").lower() or None,
}

_PRIORITY_ORDER = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}

SORT_KEYS = tuple(_SORTERS)

# 상태 필터. 값 하나가 하나의 물음에 답한다.
_FILTERS: dict[str, Callable[[Finding], bool]] = {
    "update": lambda f: bool(f.fix and f.fix.update_available.is_true()),
    "nofix": lambda f: bool(f.verdict and "no_fix_available" in f.verdict.flags),
    "unknown": lambda f: bool(f.fix and f.fix.is_vulnerable.value == "unknown"),
    "kev": lambda f: f.intel.kev.is_true(),
    "exploit": lambda f: f.intel.exploit_available.is_true(),
}

FILTER_KEYS = tuple(_FILTERS)


@dataclass(frozen=True)
class Page:
    findings: tuple[Finding, ...]
    total: int          # 필터를 적용한 뒤의 건수
    scan_total: int     # 스캔 전체 건수
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.findings) < self.total


def _matches_text(finding: Finding, needle: str) -> bool:
    if not needle:
        return True
    haystack = " ".join((
        finding.intel.cve,
        " ".join(finding.intel.aliases),
        finding.installed.name,
        finding.advisory.advisory_package,
    )).lower()
    return needle in haystack


def apply(
    findings: Iterable[Finding],
    *,
    sort: str = "priority",
    order: str = "asc",
    priority: str = "",
    package_type: str = "",
    status: str = "",
    query: str = "",
    offset: int = 0,
    limit: int = 100,
) -> Page:
    """필터 → 정렬 → 자르기. 순서가 중요하다 — total은 자르기 **전** 건수다."""
    findings = tuple(findings)
    scan_total = len(findings)

    needle = query.strip().lower()
    status_check = _FILTERS.get(status)

    kept = tuple(
        f for f in findings
        if (not priority or (f.verdict and f.verdict.priority.value == priority))
        and (not package_type or f.installed.type == package_type)
        and (status_check is None or status_check(f))
        and _matches_text(f, needle)
    )

    getter = _SORTERS.get(sort) or _SORTERS["priority"]
    descending = order == "desc"

    def key(finding: Finding):
        value = getter(finding)
        # 첫 칸이 정렬 방향과 무관하게 미확인을 뒤로 민다.
        if value is None or value == "":
            return (1, 0 if descending else 0)
        return (0, _invert(value) if descending else value)

    ordered = sorted(kept, key=key)

    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    return Page(
        findings=tuple(ordered[offset : offset + limit]),
        total=len(kept),
        scan_total=scan_total,
        offset=offset,
        limit=limit,
    )


class _Reversed:
    """문자열을 역순으로 정렬하기 위한 감싸개.

    숫자는 부호를 뒤집으면 되지만 문자열은 그럴 수 없다. `reverse=True`를 쓰면
    미확인을 뒤로 미는 첫 칸까지 함께 뒤집혀 미확인이 맨 앞으로 온다.
    """

    __slots__ = ("value",)

    def __init__(self, value: str):
        self.value = value

    def __lt__(self, other: "_Reversed") -> bool:
        return other.value < self.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Reversed) and other.value == self.value


def _invert(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return -value
    return _Reversed(str(value))


def package_types(findings: Iterable[Finding]) -> list[str]:
    """필터 목록에 채울 패키지 유형. '생태계'라는 말은 쓰지 않는다."""
    return sorted({f.installed.type for f in findings if f.installed.type})
