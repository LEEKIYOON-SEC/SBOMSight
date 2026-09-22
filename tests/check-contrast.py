"""글자와 바탕의 대비가 읽을 만한가 — **브라우저가 실제로 칠한 색으로.**

**왜 JUnit 이 아니라 여기인가.** 대비는 `app.css` 의 변수만 봐서는 알 수 없다.
글자색은 `.faint` 가 주고 바탕은 세 겹 위의 `tbody tr:hover` 가 주는 식으로
겹쳐 쌓이고, 투명한 바탕은 조상까지 올라가 봐야 실제 색이 나온다. 그려진
화면에서 계산된 값을 읽는 것이 유일한 방법이다.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 scripts/check-contrast.py

기준은 WCAG 2.1 AA 다.

    보통 글자            4.5 : 1
    큰 글자              3.0 : 1   (24px 이상, 또는 굵은 18.7px 이상)

**색만으로 뜻을 나르지 않는다는 규칙(§5-15)과는 다른 이야기다.** 여기서 보는
것은 "눈에 보이는가" 이고, 그쪽은 "색을 못 가려도 읽히는가" 다. 둘 다 필요하다.

낮은 자리가 나오면 그 자리의 선택자·글자·색·비율을 낸다. 고치는 법은 대개
`--fg-faint` 처럼 **팔레트의 옅은 색을 한 칸 진하게** 하는 것이고, 그것은
승인받은 시안에서 온 값이라 눈으로 함께 보고 정해야 한다.
"""
import sys
from playwright.sync_api import sync_playwright

from screens import resolve

SCREENS = ["/", "/?view=zones", "/assets/1", "/assets/1?tab=vulns", "/assets/1?tab=packages",
           "/assets/1?tab=history", "/assets/1?tab=actions", "/vulns", "/vulns?group=cve",
           "@CVE상세", "/packages", "/packages?open=jackson-databind",
           "/actions", "/actions?tab=analyses", "@조치상세", "/reports", "/reports/zone",
           "/settings", "/settings?tab=ips", "/settings?tab=tools", "/settings/audit",
           "/me", "/assets/import", "/login"]

PORT = sys.argv[1] if len(sys.argv) > 1 else "8443"
BASE = f"https://localhost:{PORT}"

# 화면에서 계산된 색을 그대로 읽어 비율을 낸다. 바탕이 투명하면 조상으로
# 올라가고, 끝까지 투명하면 흰색으로 본다(body 가 흰색이다).
MEASURE = r"""
() => {
  const lum = (c) => {
    const f = c.map(v => { v /= 255; return v <= .03928 ? v/12.92 : Math.pow((v+.055)/1.055, 2.4); });
    return .2126*f[0] + .7152*f[1] + .0722*f[2];
  };
  const parse = (s) => {
    // 크로뮴은 `light-dark()` · `color-mix()` 로 정한 색을 `color(srgb …)` 로
    // 돌려준다. 그 꼴을 못 읽으면 **바탕이 없는 것으로 보고 흰색으로 세어**
    // 멀쩡한 자리를 낮은 대비로 잡는다(Tabler 를 깐 뒤 그렇게 됐다).
    const srgb = s.match(/color\(srgb\s+([^)]+)\)/);
    if (srgb) {
      const p = srgb[1].split(/[\s/]+/).filter(Boolean).map(Number);
      return { rgb: p.slice(0, 3).map(v => v * 255), a: p.length > 3 ? p[3] : 1 };
    }
    const m = s.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return { rgb: p.slice(0, 3), a: p.length > 3 ? p[3] : 1 };
  };
  const mix = (fg, bg, a) => fg.map((v, i) => v * a + bg[i] * (1 - a));
  const bgOf = (el) => {
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0) {
        return c.a === 1 ? c.rgb : mix(c.rgb, bgOf(n.parentElement) || [255,255,255], c.a);
      }
    }
    // 끝까지 투명하면 흰색(body 가 흰색이다). 읽을 수 없는 꼴이면 null 을
    // 돌려준다 — 흰색으로 치면 멀쩡한 자리가 낮은 대비로 잡힌다.
    return [255, 255, 255];
  };
  const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m);
    return (x + .05) / (y + .05);
  };
  const path = (el) => {
    const bits = [];
    for (let n = el; n && n.tagName !== 'BODY' && bits.length < 3; n = n.parentElement) {
      bits.unshift(n.tagName.toLowerCase() + (n.className && typeof n.className === 'string'
        ? '.' + n.className.trim().split(/\s+/).slice(0, 2).join('.') : ''));
    }
    return bits.join(' > ');
  };

  const out = [];
  document.querySelectorAll('body *').forEach(el => {
    // 제 글자를 직접 가진 것만 본다. 부모까지 세면 같은 글자를 여러 번 잰다.
    const own = [...el.childNodes]
        .filter(n => n.nodeType === 3 && n.textContent.trim())
        .map(n => n.textContent.trim()).join(' ');
    if (!own) return;
    const box = el.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) return;

    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || st.opacity === '0') return;
    const fg = parse(st.color);
    if (!fg) return;
    const bg = bgOf(el);
    if (!bg) { out.push({ unreadable: true, where: path(el), color: st.color }); return; }
    const size = parseFloat(st.fontSize);
    const weight = parseInt(st.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3 : 4.5;
    const got = ratio(fg.a === 1 ? fg.rgb : mix(fg.rgb, bg, fg.a), bg);
    if (got + 0.005 < need) {
      out.push({ where: path(el), text: own.slice(0, 34),
                 color: st.color, bg: `rgb(${bg.map(Math.round).join(', ')})`,
                 size: Math.round(size * 10) / 10, weight,
                 got: Math.round(got * 100) / 100, need });
    }
  });
  return out;
}
"""

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.goto(BASE + "/login")
    pg.fill('input[name=username]', 'admin')
    pg.fill('input[name=password]', 'devadmin1234')
    pg.click('button[type=submit]')
    pg.wait_for_load_state('networkidle')
    # 마우스가 단추 위에 남아 있으면 그 단추만 hover 색으로 잡힌다. 치운다.
    pg.mouse.move(0, 0)

    # 같은 자리를 화면마다 다시 내지 않는다. 한 번 고치면 한 번에 사라진다.
    seen = {}
    unreadable = {}
    for url in resolve(pg, BASE, SCREENS):
        r = pg.goto(BASE + url)
        if r.status >= 400:
            print(f"  {url}  HTTP {r.status}")
            continue
        pg.wait_for_load_state('networkidle')
        for hit in pg.evaluate(MEASURE):
            if hit.get('unreadable'):
                unreadable.setdefault((hit['where'], hit['color']), url)
                continue
            key = (hit['where'], hit['color'], hit['bg'], hit['size'])
            seen.setdefault(key, (hit, url))

    for hit, url in sorted(seen.values(), key=lambda h: h[0]['got']):
        print(f"  {hit['got']:>5.2f} : 1  (필요 {hit['need']})  {hit['size']}px/{hit['weight']}"
              f"  {hit['color']} on {hit['bg']}")
        print(f"             {hit['where']}   {hit['text']!r}   ({url})")

    if unreadable:
        print(f"\n색을 읽지 못한 자리 {len(unreadable)}개 (oklab 등 — 세지 않았다)")
        for (where, color), url in list(unreadable.items())[:5]:
            print(f"   {where}  {color}  ({url})")

    print(f"\n대비가 낮은 자리 {len(seen)}개 — WCAG 2.1 AA (보통 4.5:1 · 큰 글자 3:1)")
    b.close()
