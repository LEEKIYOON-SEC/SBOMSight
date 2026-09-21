"""화면이 내놓는 주소가 사람이 읽을 수 있는가.

**왜 JUnit 이 아니라 여기인가.** 링크는 화면마다 조각마다 흩어져 있고, 실제로
그려진 뒤의 모양을 봐야 안다. HTML 안에는 멀쩡한 링크 표현식이 들어 있고
시험도 전부 통과하는데, 그려진 주소는 이렇다:

    /packages?zone=&type=&q=&vulnerable=false&mixed=false&open=glibc

동작은 한다. 그런데 **그 주소가 결재 문서에 붙고 옆자리에 전달된다.**
`vulnerable=false` 는 더 나쁘다 — 안 고른 것이 아니라 *끄기로 골랐다* 고 읽힌다.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 scripts/check-links.py

원인은 대개 하나다 — 타임리프의 `@{/x(a=${a}, b=${b})}` 는 **값이 없어도 이름을
적는다.** 고치는 법도 하나다: `VulnQuery.Links` 로 자바에서 만든다. 값이 빈
것은 이름째로 빠진다.

`=false` 는 저절로 틀린 것이 아니다. `/vulns?fixable=false`(수정 버전 없는 것만)
처럼 뜻이 있는 값도 있다. 그래서 빈 값은 **틀린 것**으로, `false` 는 **볼 것**
으로 따로 센다.
"""
import re
import sys
from playwright.sync_api import sync_playwright

SCREENS = ["/", "/?view=zones", "/assets/1", "/assets/1?tab=vulns", "/assets/1?tab=scans",
           "/assets/1?tab=actions", "/assets/1?tab=packages", "/vulns", "/vulns?group=cve",
           "/vulns?group=package", "/vulns/CVE-2021-44228",
           "/packages", "/packages?vulnerable=true", "/packages?mixed=true",
           "/packages?open=jackson-databind",
           "/actions", "/actions?tab=analyses", "/actions/1",
           "/reports", "/reports/zone", "/settings", "/settings?tab=ips",
           "/settings?tab=tools", "/settings/audit", "/me", "/assets/import"]

EMPTY = re.compile(r"[?&][A-Za-z_]+=(?:&|$)")
FALSE = re.compile(r"[?&][A-Za-z_]+=false(?:&|$)")
PORT = sys.argv[1] if len(sys.argv) > 1 else "8443"
BASE = f"https://localhost:{PORT}"

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    pg.goto(BASE + "/login")
    pg.fill('input[name=username]', 'admin')
    pg.fill('input[name=password]', 'devadmin1234')
    pg.click('button[type=submit]')
    pg.wait_for_load_state('networkidle')

    empty, false = 0, 0
    for url in SCREENS:
        r = pg.goto(BASE + url)
        if r.status >= 400:
            print(f"  {url}  HTTP {r.status}")
            continue
        pg.wait_for_load_state('networkidle')
        hrefs = pg.evaluate(
            "() => [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href'))")
        seen = set()
        for href in hrefs:
            if not href or '?' not in href or href in seen:
                continue
            marks = []
            if EMPTY.search(href):
                marks.append("빈 값")
                empty += 1
            if FALSE.search(href):
                marks.append("false")
                false += 1
            if marks:
                seen.add(href)
                print(f"  {url:36} [{' · '.join(marks)}] {href}")

    print(f"\n빈 값이 붙은 링크 {empty}개 · `=false` 가 붙은 링크 {false}개")
    b.close()
