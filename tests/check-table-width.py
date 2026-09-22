"""모든 화면의 표가 칸 안에 드는가.

**왜 JUnit 이 아니라 여기인가.** 표가 칸을 넘는지는 글자 폭을 실제로 재야
알 수 있고, 그것은 브라우저만 한다. HTML 안에는 `적기` 단추가 멀쩡히 들어
있어서 화면 시험은 전부 통과했는데, 띄워 보니 그 칸이 통째로 화면 밖에
밀려 있었다 — 이 화면에서 가장 많이 누르는 것이 안 보이고 있었다.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 scripts/check-table-width.py 1280
    python3 scripts/check-table-width.py 1024      # 노트북 폭

넘치는 표마다 몇 px 넘쳤고 각 칸이 몇 px 를 먹고 있는지 낸다. 고치는 법은
대개 하나다 — **글자가 들어가는 칸에서 `tight`(줄바꿈 금지)를 뺀다.** 모든
칸이 `tight` 면 표에 줄어들 자리가 없다.

**1200px 이하에서 넘치는 것은 고장이 아니라 결정이다.** 취약점 표는 아홉 칸이고
CVE 번호 하나가 110px 쯤을 쓴다 — 1024px 에서 표에 주어지는 폭은 788px 이라
물리적으로 안 들어간다. 억지로 넣으면 한국어가 한 글자씩 세로로 쪼개진다(해 봤다).
그래서 좁을 때는 **밀되 첫 칸을 붙여 둔다** (`app.css` 의 `@media (max-width:1200px)`).

그러므로 **봐야 하는 폭은 1280px 이상**이다. 거기서 넘치면 고칠 것이 있다는 뜻이고,
1024px 의 숫자는 "밀어서 보는 표가 몇 개인가" 로 읽는다.
"""
import sys
from playwright.sync_api import sync_playwright

from screens import resolve

SCREENS = ["/", "/?view=zones", "/assets/1", "/assets/1?tab=vulns", "/assets/1?tab=scans",
           "/assets/1?tab=actions", "/assets/1?tab=packages", "/vulns", "/vulns?group=cve",
           "/vulns?group=package", "@CVE상세",
           # **수정 버전 없는 것만도 본다.** `현재 → 목표` 칸에 `수정 버전 없음`
           # 딱지가 서면 그 칸이 넓어진다 — 앞서 여기만 18px 넘치고 있었는데,
           # 폭을 재 볼 때 쓴 자료가 전부 수정 버전이 있는 것이라 안 보였다.
           # 보고서 4장이 통째로 다루는 것이 이 행들이다.
           "/vulns?fixable=false",
           # 펼친 줄은 표 안에 표를 둔다 — 바깥 표에 자리가 없으면 안쪽이 눌린다.
           "/packages", "/packages?vulnerable=true", "/packages?open=jackson-databind",
           # 이 둘은 번호가 자료마다 다르다. 띄운 앱에서 찾아 넣는다(아래) —
           # 하드코딩해 두었더니 404 로 조용히 건너뛰고 있었고, 그동안 두 화면은
           # 한 번도 재지 않았다.
           "/actions", "/actions?tab=analyses", "@조치상세",
           "/reports", "/reports/scan/3", "/reports/zone", "/settings", "/settings?tab=ips",
           "/settings?tab=tools", "/settings/audit", "/me", "/assets/import"]
WIDTH = int(sys.argv[1]) if len(sys.argv) > 1 else 1280

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": WIDTH, "height": 900})
    pg = ctx.new_page()
    pg.goto("https://localhost:8443/login")
    pg.fill('input[name=username]','admin'); pg.fill('input[name=password]','devadmin1234')
    pg.click('button[type=submit]'); pg.wait_for_load_state('networkidle')

    screens = resolve(pg, "https://localhost:8443", SCREENS)

    over = 0
    for url in screens:
        r = pg.goto("https://localhost:8443" + url)
        if r.status >= 400:
            print(f"  {url}  HTTP {r.status}"); continue
        pg.wait_for_load_state('networkidle')
        rows = pg.evaluate("""() => {
          const out = [];
          document.querySelectorAll('table').forEach((t, i) => {
            const host = t.closest('.table-scroll') || t.parentElement;
            const w = Math.round(t.getBoundingClientRect().width);
            const avail = host.clientWidth;
            if (w > avail + 1) {
              const cols = [...t.querySelectorAll('thead th')].map(th =>
                  (th.textContent.trim() || '(빈칸)') + ':' + Math.round(th.getBoundingClientRect().width));
              out.push({i, w, avail, cols: cols.join(' ')});
            }
          });
          return out;
        }""")
        for row in rows:
            over += 1
            print(f"  {url}  표#{row['i']}  {row['w']} > {row['avail']}  ({row['w']-row['avail']}px 넘침)")
            print(f"      {row['cols']}")
    if WIDTH >= 1280:
        print(f"\n폭 {WIDTH}px — 넘치는 표 {over}개"
              + ("  (고칠 것이 있다)" if over else "  (좋다)"))
    else:
        print(f"\n폭 {WIDTH}px — 밀어서 보는 표 {over}개"
              " (1200px 이하는 결정된 동작 — 첫 칸이 붙어 있다)")
    b.close()
