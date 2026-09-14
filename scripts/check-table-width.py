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
"""
import sys
from playwright.sync_api import sync_playwright

SCREENS = ["/", "/?view=zones", "/assets/1", "/assets/1?tab=vulns", "/assets/1?tab=scans",
           "/assets/1?tab=actions", "/vulns", "/vulns?group=cve", "/vulns?group=package",
           "/vulns/CVE-2021-44228", "/actions", "/actions?tab=analyses", "/actions/1",
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

    over = 0
    for url in SCREENS:
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
    print(f"\n폭 {WIDTH}px — 넘치는 표 {over}개")
    b.close()
