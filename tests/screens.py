"""점검 스크립트가 **실제로 그 화면을 지나가게** 한다.

세 스크립트(폭·대비·링크)가 `/vulns/CVE-2021-44228` 과 `/actions/1` 을
글자 그대로 적어 두고 있었다. 그 번호는 **자료마다 다르다** — 없으면 404 가
찍히고 스크립트는 다음 화면으로 넘어간다. 조용히 넘어가므로 "넘치는 표
0개" 가 나와도 그 두 화면은 한 번도 재지 않은 것이다.

실제로 그렇게 숨었다. 취약점 표가 `수정 버전 없음` 딱지가 붙는 행에서만
18px 넘치고 있었는데, 폭을 재는 목록에 그 화면(`?fixable=false`)이 없었다.

그래서 **띄운 앱에서 찾아 넣는다.** 목록 화면의 표 안에서 상세로 가는 첫
링크를 집는다 — 화면 머리의 `CSV` 는 같은 앞머리를 쓰지만 누르면 내려받기가
시작되어 그리로 갈 수 없으므로 표 안에서만 찾는다.

찾지 못하면 **건너뛰되 그 사실을 찍는다.** 자료가 없는 것과 재 봤더니
괜찮은 것은 다른 말이다.
"""

#: 목록 화면 → 그 안에서 상세로 가는 링크의 꼴
PLACEHOLDERS = {
    "@CVE상세": ("/vulns?group=cve", r"^/vulns/[^?]+$"),
    "@조치상세": ("/actions", r"^/actions/\d+$"),
}

_FIND = """(p) => {
    const a = [...document.querySelectorAll('table.table tbody a[href]')]
                .map(x => x.getAttribute('href'))
                .find(h => h && new RegExp(p).test(h));
    return a || null;
}"""


def resolve(pg, base, screens):
    """목록의 `@…` 자리를 띄운 앱에서 찾은 주소로 바꾼다.

    :param pg: 로그인까지 끝낸 playwright 페이지
    :param base: `https://localhost:8443` 같은 앞머리
    :param screens: 주소 목록. `@CVE상세`·`@조치상세` 가 섞여 있어도 된다
    :return: 실제로 열 수 있는 주소만 남은 목록
    """
    out = []
    for url in screens:
        if not url.startswith("@"):
            out.append(url)
            continue
        listing, pattern = PLACEHOLDERS[url]
        pg.goto(base + listing)
        pg.wait_for_load_state("networkidle")
        found = pg.evaluate(_FIND, pattern)
        if found is None:
            print(f"  {url}  그 화면으로 가는 링크가 없어 건너뜀 (자료 없음)")
            continue
        out.append(found)
    return out
