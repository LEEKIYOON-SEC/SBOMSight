"""생태계별 버전 비교자와 제약식(constraint) 평가.

FixAnalysis("우리가 취약한가")의 정확도가 통째로 이 모듈에 달려 있다.
그래서 rpm과 deb는 요령껏 흉내내지 않고 원 구현의 알고리즘을 그대로 옮겼다:

  * rpm   — rpmvercmp.c 의 rpmvercmp()  (`~` 정렬, `^` 정렬, 숫자>알파 규칙 포함)
  * deb   — dpkg 의 verrevcmp()         (order() 가중치 규칙 포함)
  * semver, pep440, generic

비교할 수 없으면 **None을 돌려준다.** 호출부는 이를 Ternary.UNKNOWN으로
옮긴다. 비표준 버전 문자열을 만났을 때 "취약하지 않음"이라고 답하는 것은
거짓말이고, 그 거짓말은 패치 누락으로 이어진다.

벡터 파일(tests/fixtures/version-vectors.json)로 채점한다. rpm 케이스는
rpm 프로젝트의 rpmvercmp 테스트 스위트에서 그대로 가져왔다.
"""

from __future__ import annotations

import re
from typing import Callable

__all__ = [
    "compare",
    "comparator_for",
    "satisfies",
    "version_gap",
    "rpm_compare",
    "deb_compare",
    "semver_compare",
    "pep440_compare",
    "generic_compare",
]


# ---------------------------------------------------------------------------
# rpm — rpmvercmp.c 포팅
# ---------------------------------------------------------------------------


def _rpmvercmp(one: str, two: str) -> int:
    """rpm의 rpmvercmp(). 버전 문자열 하나(epoch/release 분리 전)를 비교한다."""
    if one == two:
        return 0

    i, j = 0, 0
    len1, len2 = len(one), len(two)

    def alnum(c: str) -> bool:
        return c.isascii() and c.isalnum()

    while i < len1 or j < len2:
        # 영숫자도 ~ 도 ^ 도 아닌 구분자는 건너뛴다.
        while i < len1 and not (alnum(one[i]) or one[i] in "~^"):
            i += 1
        while j < len2 and not (alnum(two[j]) or two[j] in "~^"):
            j += 1

        c1 = one[i] if i < len1 else ""
        c2 = two[j] if j < len2 else ""

        # `~`는 무엇보다도 앞선다 — 문자열의 끝보다도 앞선다.
        if c1 == "~" or c2 == "~":
            if c1 != "~":
                return 1
            if c2 != "~":
                return -1
            i += 1
            j += 1
            continue

        # `^`는 개념은 ~와 같으나, 한쪽이 끝났으면(base version) 다른 쪽이 높다.
        if c1 == "^" or c2 == "^":
            if not c1:
                return -1
            if not c2:
                return 1
            if c1 != "^":
                return 1
            if c2 != "^":
                return -1
            i += 1
            j += 1
            continue

        # 어느 한쪽이 끝났으면 루프 종료.
        if not (c1 and c2):
            break

        # 완전히 숫자이거나 완전히 알파인 첫 세그먼트를 떼어낸다.
        start1, start2 = i, j
        if one[i].isdigit():
            while i < len1 and one[i].isdigit():
                i += 1
            while j < len2 and two[j].isdigit():
                j += 1
            isnum = True
        else:
            while i < len1 and one[i].isalpha():
                i += 1
            while j < len2 and two[j].isalpha():
                j += 1
            isnum = False

        seg1 = one[start1:i]
        seg2 = two[start2:j]

        # 한쪽만 세그먼트가 비었다 = 타입이 다르다. 숫자가 알파보다 항상 높다.
        if not seg2:
            return 1 if isnum else -1

        if isnum:
            seg1 = seg1.lstrip("0")
            seg2 = seg2.lstrip("0")
            if len(seg1) > len(seg2):
                return 1
            if len(seg2) > len(seg1):
                return -1

        if seg1 != seg2:
            return -1 if seg1 < seg2 else 1

    # 모든 세그먼트가 같았다면, 남은 문자가 있는 쪽이 높다.
    rest1 = i < len1
    rest2 = j < len2
    if not rest1 and not rest2:
        return 0
    return -1 if not rest1 else 1


_EVR_RE = re.compile(r"^(?:(?P<epoch>\d+):)?(?P<version>[^-]*)(?:-(?P<release>.*))?$")


def _split_evr(value: str) -> tuple[str, str, str] | None:
    m = _EVR_RE.match(value.strip())
    if not m:
        return None
    epoch = m.group("epoch") or "0"
    version = m.group("version") or ""
    release = m.group("release") or ""
    if not version:
        return None
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int | None:
    """rpm EVR(epoch:version-release) 비교."""
    left = _split_evr(a)
    right = _split_evr(b)
    if left is None or right is None:
        return None

    e1, v1, r1 = left
    e2, v2, r2 = right

    rc = _rpmvercmp(e1, e2)
    if rc:
        return rc
    rc = _rpmvercmp(v1, v2)
    if rc:
        return rc
    # release가 한쪽에만 있으면 비교하지 않는다. advisory가 "5.6.2"라고만
    # 말했는데 설치본이 "5.6.2-1.el9"인 경우 release로 갈라서는 안 된다.
    if not r1 or not r2:
        return 0
    return _rpmvercmp(r1, r2)


# ---------------------------------------------------------------------------
# deb — dpkg verrevcmp 포팅
# ---------------------------------------------------------------------------


def _deb_order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        # 숫자가 아닌 구간을 order() 가중치로 비교
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) else 0
            bc = _deb_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # 선행 0 제거
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        # 숫자 구간을 자릿수 → 사전순으로 비교
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


_DEB_RE = re.compile(r"^(?:(?P<epoch>\d+):)?(?P<upstream>[^:]*?)(?:-(?P<revision>[^-]*))?$")


def deb_compare(a: str, b: str) -> int | None:
    ma = _DEB_RE.match(a.strip())
    mb = _DEB_RE.match(b.strip())
    if not ma or not mb:
        return None

    ea = int(ma.group("epoch") or 0)
    eb = int(mb.group("epoch") or 0)
    if ea != eb:
        return -1 if ea < eb else 1

    rc = _verrevcmp(ma.group("upstream") or "", mb.group("upstream") or "")
    if rc:
        return rc

    ra, rb = ma.group("revision"), mb.group("revision")
    if not ra or not rb:
        return 0
    return _verrevcmp(ra, rb)


# ---------------------------------------------------------------------------
# semver
# ---------------------------------------------------------------------------


_SEMVER_RE = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)


def _semver_parse(value: str) -> tuple[int, int, int, list[str]] | None:
    m = _SEMVER_RE.match(value.strip())
    if not m:
        return None
    pre = m.group("prerelease")
    return (
        int(m.group("major")),
        int(m.group("minor") or 0),
        int(m.group("patch") or 0),
        pre.split(".") if pre else [],
    )


def _cmp_prerelease(a: list[str], b: list[str]) -> int:
    # prerelease가 없는 쪽이 더 높다 (1.0.0 > 1.0.0-rc1).
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for x, y in zip(a, b):
        xnum, ynum = x.isdigit(), y.isdigit()
        if xnum and ynum:
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
        elif xnum != ynum:
            return -1 if xnum else 1   # 숫자 식별자가 문자 식별자보다 낮다
        elif x != y:
            return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def semver_compare(a: str, b: str) -> int | None:
    pa, pb = _semver_parse(a), _semver_parse(b)
    if pa is None or pb is None:
        return None
    for x, y in zip(pa[:3], pb[:3]):
        if x != y:
            return -1 if x < y else 1
    return _cmp_prerelease(pa[3], pb[3])


# ---------------------------------------------------------------------------
# PEP 440
# ---------------------------------------------------------------------------


_PEP440_RE = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$",
    re.IGNORECASE,
)

_PRE_NORM = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def _pep440_key(value: str):
    m = _PEP440_RE.match(value)
    if not m:
        return None

    epoch = int(m.group("epoch") or 0)
    release = tuple(int(p) for p in m.group("release").split("."))
    # 후행 0을 제거해 1.0 == 1.0.0 이 되게 한다.
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    release = tuple(trimmed)

    pre = None
    if m.group("pre_l"):
        letter = m.group("pre_l").lower()
        letter = _PRE_NORM.get(letter, letter)
        pre = (letter, int(m.group("pre_n") or 0))

    post = None
    if m.group("post_n1") is not None:
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n2") or 0)

    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None

    # 정렬 키: dev < pre < release < post 순서가 나오도록 튜플을 만든다.
    if pre is None and post is None and dev is not None:
        pre_key = (-1, "", 0)          # x.y.dev0 은 x.y 의 모든 pre 보다 낮다
    elif pre is None:
        pre_key = (1, "", 0)           # pre 없음 = 정식 릴리스
    else:
        pre_key = (0, pre[0], pre[1])

    post_key = (0, 0) if post is None else (1, post)
    dev_key = (1, 0) if dev is None else (0, dev)   # dev 있음이 더 낮다

    return (epoch, release, pre_key, post_key, dev_key)


def pep440_compare(a: str, b: str) -> int | None:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return None
    if ka == kb:
        return 0
    return -1 if ka < kb else 1


# ---------------------------------------------------------------------------
# generic — 최후의 수단
# ---------------------------------------------------------------------------


_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")


def generic_compare(a: str, b: str) -> int | None:
    """숫자/알파 런으로 쪼개 왼쪽부터 비교하는 느슨한 비교.

    정확도를 보장하지 않는다. 이 비교자가 쓰였다는 사실은 리포트에
    `comparator: generic`으로 표기되어 사람이 알아볼 수 있게 한다.
    """
    ta = _TOKEN_RE.findall(a.strip())
    tb = _TOKEN_RE.findall(b.strip())
    if not ta or not tb:
        return None
    for x, y in zip(ta, tb):
        xnum, ynum = x.isdigit(), y.isdigit()
        if xnum and ynum:
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
        elif xnum != ynum:
            return 1 if xnum else -1   # 숫자를 더 높게 본다 (rpm 관례)
        elif x.lower() != y.lower():
            return -1 if x.lower() < y.lower() else 1
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


# ---------------------------------------------------------------------------
# 디스패치
# ---------------------------------------------------------------------------


_COMPARATORS: dict[str, Callable[[str, str], int | None]] = {
    "rpm": rpm_compare,
    "deb": deb_compare,
    "semver": semver_compare,
    "pep440": pep440_compare,
    "generic": generic_compare,
}

# SBOM/Grype의 패키지 타입·생태계 → 비교자
_ECOSYSTEM_COMPARATOR = {
    "rpm": "rpm",
    "rhel": "rpm",
    "redhat": "rpm",
    "centos": "rpm",
    "rocky": "rpm",
    "almalinux": "rpm",
    "amazonlinux": "rpm",
    "sles": "rpm",
    "opensuse": "rpm",
    "deb": "deb",
    "dpkg": "deb",
    "debian": "deb",
    "ubuntu": "deb",
    "npm": "semver",
    "javascript": "semver",
    "node": "semver",
    "go-module": "semver",
    "golang": "semver",
    "go": "semver",
    "cargo": "semver",
    "rust-crate": "semver",
    "gem": "semver",
    "ruby": "semver",
    "composer": "semver",
    "php-composer": "semver",
    "python": "pep440",
    "pypi": "pep440",
    "python-pkg": "pep440",
    "wheel": "pep440",
    "egg": "pep440",
}


def comparator_for(ecosystem: str) -> str:
    """생태계 이름을 비교자 이름으로 옮긴다. 모르면 generic."""
    if not ecosystem:
        return "generic"
    return _ECOSYSTEM_COMPARATOR.get(ecosystem.strip().lower(), "generic")


def compare(a: str, b: str, comparator: str = "generic") -> int | None:
    """a와 b를 비교해 -1/0/1을 준다. 비교 불가면 None."""
    if a is None or b is None:
        return None
    a, b = a.strip(), b.strip()
    if not a or not b:
        return None
    fn = _COMPARATORS.get(comparator, generic_compare)
    try:
        return fn(a, b)
    except (ValueError, TypeError, IndexError):
        return None


# ---------------------------------------------------------------------------
# 제약식 평가
# ---------------------------------------------------------------------------

# `<<` 와 `>>` 는 dpkg의 엄격 비교 연산자다. 긴 것을 먼저 매칭해야 `<<`가
# `<` 로 잘려 나머지가 피연산자에 섞이는 사고가 나지 않는다.
_OP_RE = re.compile(r"^\s*(<<|>>|>=|<=|==|!=|=|>|<)?\s*(.+?)\s*$")
_OPS = {
    "<": lambda rc: rc < 0,
    "<<": lambda rc: rc < 0,
    "<=": lambda rc: rc <= 0,
    ">": lambda rc: rc > 0,
    ">>": lambda rc: rc > 0,
    ">=": lambda rc: rc >= 0,
    "=": lambda rc: rc == 0,
    "==": lambda rc: rc == 0,
    "!=": lambda rc: rc != 0,
}

# 피연산자로 버전이 아닌 것이 들어오면 비교자에 따라 조용히 통과해 버릴 수
# 있다. 버전 문자열에 나올 수 없는 문자가 섞이면 '판단 불가'로 돌린다.
_OPERAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:~^+_*-]*$")


def _eval_clause(version: str, clause: str, comparator: str) -> bool | None:
    m = _OP_RE.match(clause)
    if not m:
        return None
    op = m.group(1) or "="
    operand = m.group(2)
    if not _OPERAND_RE.match(operand):
        # 연산자를 못 알아봤거나 제약식이 우리가 아는 문법이 아니다.
        # 억지로 비교해 참/거짓을 만들어 내는 것보다 판단 불가가 정직하다.
        return None
    # Grype는 rpm 제약에 "0:4.18.0-513.el8" 처럼 epoch를 붙여 준다. 그대로 넘긴다.
    rc = compare(version, operand, comparator)
    if rc is None:
        return None
    return _OPS[op](rc)


def satisfies(version: str, constraint: str, comparator: str = "generic") -> bool | None:
    """version이 constraint를 만족하는지.

    지원 문법 (Grype가 내보내는 형태):
        "< 5.6.2"
        ">=5.6.0,<5.6.2"                 쉼표 = AND
        "<1.2.3 || >=2.0.0,<2.1.0"       || = OR
        "" (제약 없음)                    → None(판단 불가)

    비교 불가한 절이 하나라도 있으면 그 AND 그룹은 판단 불가로 본다.
    한 OR 그룹이라도 확실히 참이면 참, 전부 확실히 거짓이면 거짓,
    그 외에는 None.
    """
    if not constraint or not constraint.strip():
        return None
    if not version or not version.strip():
        return None

    # Grype는 "제약 없음"을 versionConstraint: "none" 으로 표현한다. 이는
    # 해당 패키지의 **모든 버전이 영향 범위**라는 뜻이지, 버전 이름이 아니다.
    # normalize가 "*"로 옮겨 주지만 원문도 함께 받아 둔다.
    if constraint.strip().lower() in ("*", "none", "all"):
        return True

    saw_unknown = False
    for or_group in constraint.split("||"):
        clauses = [c for c in or_group.split(",") if c.strip()]
        if not clauses:
            continue
        group = True
        group_unknown = False
        for clause in clauses:
            rc = _eval_clause(version, clause, comparator)
            if rc is None:
                group_unknown = True
                break
            if not rc:
                group = False
                break
        if group_unknown:
            saw_unknown = True
            continue
        if group:
            return True
    return None if saw_unknown else False


def version_gap(installed: str, fixed: str, comparator: str = "generic") -> str:
    """설치 버전과 수정 버전 사이의 거리를 major/minor/patch로 요약한다."""
    rc = compare(installed, fixed, comparator)
    if rc is None:
        # 버전을 비교조차 못 하는데 격차를 말할 수는 없다.
        return "unknown"
    if rc == 0:
        return "none"
    ta = [int(t) for t in _TOKEN_RE.findall(installed or "") if t.isdigit()]
    tb = [int(t) for t in _TOKEN_RE.findall(fixed or "") if t.isdigit()]
    if not ta or not tb:
        return "unknown"
    for idx, label in enumerate(("major", "minor", "patch")):
        x = ta[idx] if idx < len(ta) else 0
        y = tb[idx] if idx < len(tb) else 0
        if x != y:
            return label
    return "patch"
