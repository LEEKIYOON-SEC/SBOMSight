"""한 줄에 나란히 선 것들의 **밑선이 맞는가** — 재서 센다.

**왜 JUnit 이 아니라 여기인가.** "대칭이 안 맞는다" 는 그려진 뒤의 좌표
이야기다. HTML 만 보면 `<label>구역 <select>` 와
`<label for>구역</label><select id>` 는 둘 다 멀쩡해 보이지만, 앞의 것은
`form-label` 이 블록이라 **고르개가 글자 아래로 내려간다** — 그 칸만 두 줄이
되고 옆 칸과 밑선이 어긋난다. 실제로 취약점·패키지·대응 화면이 그랬다.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 scripts/check-rows.py

거르개 줄(한 줄에 칸이 둘 이상인 flex 줄)마다 칸들의 **세로 중심**을 재서,
3px 넘게 벗어난 줄을 찍는다. 3px 은 글꼴 높이 차이로 생기는 흔들림이다.

줄은 **클래스가 아니라 계산된 `display:flex`** 로 찾는다. 클래스 이름으로
고르던 때 `.report-picker`(flex 를 CSS 에서 받는다)가 빠져 있었고, 그 줄의
라벨 셋이 8px 떠 있는 것을 사람이 먼저 봤다.

세로로 쌓는 form(계정 추가 · 일괄 등록)은 일부러 라벨이 위에 있다 —
`flex-direction: column` 인 줄과 `align-items` 가 `center` 가 아닌 줄의
라벨 검사는 건너뛴다.
"""

import sys, collections
from playwright.sync_api import sync_playwright

SCREENS = ["/", "/?view=zones", "/assets/1", "/assets/1?tab=vulns", "/assets/1?tab=packages",
           "/assets/1?tab=history", "/assets/1?tab=actions", "/vulns", "/vulns?group=cve",
           "/packages", "/actions", "/actions?tab=analyses", "/reports", "/reports/zone",
           "/settings", "/settings?tab=ips", "/settings?tab=tools", "/settings/audit",
           "/me", "/assets/import"]

MEASURE = r"""
() => {
  const out = [];
  // **클래스가 아니라 그려진 모양으로 찾는다.** 앞서는
  // `form.d-flex, .d-flex.flex-wrap, .card-body.d-flex` 로 골랐는데,
  // 보고서 뽑는 줄(`.report-picker`)은 flex 를 CSS 에서 받으므로 그 셋 중
  // 어디에도 안 걸렸다 — 라벨 셋만 8px 떠 있는 것을 사람이 먼저 봤다.
  // 계산된 `display:flex` 이고 가로로 늘어놓는 것이면 전부 잰다.
  const rows = Array.from(document.querySelectorAll('main *')).filter(el => {
    const cs = getComputedStyle(el);
    return cs.display === 'flex' && !cs.flexDirection.startsWith('column');
  });
  rows.forEach(row => {
    if (row.closest('.report') || row.closest('.navbar')) return;
    const items = Array.from(row.querySelectorAll(
        ':scope > input:not([type=hidden]), :scope > select, :scope > button,' +
        ':scope > a.btn, :scope > label, :scope > .btn-group, :scope > .form-check'));
    const boxes = items.map(el => {
      const r = el.getBoundingClientRect();
      return {tag: el.tagName.toLowerCase(), cls: (el.className || '').toString().slice(0, 24),
              text: (el.textContent || el.getAttribute('name') || '').trim().slice(0, 12),
              mid: Math.round((r.top + r.bottom) / 2 * 10) / 10, h: Math.round(r.height * 10) / 10};
    }).filter(b => b.h > 0);
    if (boxes.length < 2) return;
    // 줄바꿈된 줄은 여러 단으로 선다. 같은 단(중심이 8px 안)끼리 묶어 본다.
    const bands = [];
    boxes.forEach(b => {
      const band = bands.find(x => Math.abs(x.mid - b.mid) < 8);
      if (band) { band.items.push(b); band.mid = (band.mid + b.mid) / 2; }
      else { bands.push({mid: b.mid, items: [b]}); }
    });
    // 라벨이 칸을 감싸고 있으면 **그 칸이 글자 아래로 내려간다.** 라벨 높이가
    // 그 안의 칸보다 한 줄 이상 크면 그것이 증거다 — 좌표만 보면, 그 줄의
    // 다른 칸도 같이 내려앉아 있을 때 놓친다.
    //
    // **가운데로 맞추는 줄(거르개)만 본다.** 아래로 맞추는 줄
    // (`align-items-end`: 계정 추가 · 내 계정 · 일괄 등록)은 라벨을 칸 위에
    // 두는 것이 제 모양이다 — 거기서는 밑선이 맞는다.
    if (getComputedStyle(row).alignItems === 'center')
    row.querySelectorAll(':scope > label').forEach(label => {
      const ctl = label.querySelector('input:not([type=hidden]), select, textarea');
      if (!ctl) return;
      const lr = label.getBoundingClientRect(), cr = ctl.getBoundingClientRect();
      if (lr.height > cr.height + 6) {
        out.push({spread: Math.round((lr.height - cr.height) * 10) / 10,
                  row: 'label 이 칸을 감싸 두 줄 — ' + (row.className || '').toString().slice(0, 30),
                  items: [{tag: 'label', cls: (label.className || '').toString().slice(0, 24),
                           text: label.textContent.trim().slice(0, 12),
                           mid: Math.round(lr.height * 10) / 10, h: Math.round(cr.height * 10) / 10}]});
      }
    });
    bands.forEach(band => {
      if (band.items.length < 2) return;
      const mids = band.items.map(b => b.mid);
      const spread = Math.round((Math.max(...mids) - Math.min(...mids)) * 10) / 10;
      if (spread > 3) {
        out.push({spread: spread, row: (row.className || '').toString().slice(0, 40),
                  items: band.items});
      }
    });
  });
  return out;
}
"""

PORT = sys.argv[1] if len(sys.argv) > 1 else "8443"
WIDTHS = [1440, 1280]
BASE = f"https://localhost:{PORT}"

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": WIDTHS[0], "height": 900})
    pg = ctx.new_page()
    pg.goto(BASE + "/login")
    pg.fill('input[name=username]', 'admin')
    pg.fill('input[name=password]', 'devadmin1234')
    pg.click('button[type=submit]')
    pg.wait_for_load_state('networkidle')

    total = 0
    for width in WIDTHS:
        pg.set_viewport_size({"width": width, "height": 900})
        for url in SCREENS:
            r = pg.goto(BASE + url)
            if r.status >= 400:
                print(f"  {url}  HTTP {r.status}")
                continue
            pg.wait_for_load_state('networkidle')
            for bad in pg.evaluate(MEASURE):
                total += 1
                print(f"\n  폭 {width} · {url}  — {bad['spread']}px  ({bad['row']})")
                for it in bad['items']:
                    print(f"      {it['mid']:8} / {it['h']:6}  "
                          f"{it['tag']:7} {it['text']!r} {it['cls']!r}")
    print(f"\n밑선이 어긋난 줄 {total}개" + ("  (좋다)" if total == 0 else ""))
    b.close()
