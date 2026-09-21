"""단추와 칸이 화면마다 같은 크기인가 — **재서 센다.**

**왜 JUnit 이 아니라 여기인가.** 그려진 뒤의 크기는 브라우저만 안다. HTML 만
보면 `<button class="btn">` 과 `<button>` 은 둘 다 멀쩡해 보이지만, 화면에서는
31.5px 와 34.3px 로 다르게 선다. 그 차이가 쌓인 것이 "오와열이 안 맞는다" 였다.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 scripts/check-uniform.py

같은 종류가 몇 가지 모양으로 그려지고 있는지 센다. Tabler 를 바탕으로 깐
뒤에는 **단추 한 종류 + 강조 한 종류, 입력칸 한 높이**가 기준이다. 가짓수가
늘었으면 어디선가 클래스를 빠뜨렸거나 style 을 손으로 적은 것이다.

재기 전 상태(직접 짠 CSS): 단추 4가지 · 입력칸 높이 39·40·41 세 가지 ·
H2 세 가지. 그 숫자가 이 도구를 Tabler 로 옮긴 이유다.
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
  const px = (v) => Math.round(parseFloat(v) * 10) / 10;
  const out = {buttons: [], inputs: [], cells: [], headings: []};
  // 문서(보고서)와 메뉴 안쪽은 일부러 다른 모양이다. 재는 대상에서 뺀다.
  const deliberate = (el) => el.closest('.report') || el.closest('.menu-list')
                          || el.closest('.navbar');

  document.querySelectorAll('button, a.btn, .btn, input[type=submit]').forEach(el => {
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    if (!r.height || deliberate(el)) return;
    // 모서리 반경은 빼고 센다 — 묶음 단추(btn-group)는 양 끝만 둥근 것이
    // 정상이고, 그것까지 세면 같은 단추가 세 가지로 잡힌다.
    out.buttons.push({
      key: [px(r.height), s.fontSize, s.fontWeight, s.paddingTop + '/' + s.paddingLeft,
            s.borderWidth].join(' | '),
      text: el.textContent.trim().slice(0, 10), cls: el.className.toString().slice(0, 30)});
  });
  document.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=submit]), select').forEach(el => {
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    if (!r.height || deliberate(el)) return;
    out.inputs.push({key: [px(r.height), s.fontSize, s.paddingLeft, s.borderRadius].join(' | '),
                     text: (el.name || el.tagName)});
  });
  document.querySelectorAll('table tbody td').forEach(el => {
    if (deliberate(el)) return;
    const s = getComputedStyle(el);
    out.cells.push({key: [s.paddingTop, s.paddingBottom, s.paddingLeft, s.fontSize].join(' | ')});
  });
  document.querySelectorAll('h1, h2, h3').forEach(el => {
    if (deliberate(el)) return;
    const s = getComputedStyle(el);
    out.headings.push({key: [el.tagName, s.fontSize, s.fontWeight, s.marginTop, s.marginBottom].join(' | ')});
  });
  return out;
}
"""

PORT = sys.argv[1] if len(sys.argv) > 1 else "8443"
BASE = f"https://localhost:{PORT}"

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.goto(BASE + "/login")
    pg.fill('input[name=username]', 'admin')
    pg.fill('input[name=password]', 'devadmin1234')
    pg.click('button[type=submit]')
    pg.wait_for_load_state('networkidle')

    kinds = {k: collections.defaultdict(list) for k in ("buttons", "inputs", "cells", "headings")}
    for url in SCREENS:
        r = pg.goto(BASE + url)
        if r.status >= 400:
            print(f"  {url}  HTTP {r.status}")
            continue
        pg.wait_for_load_state('networkidle')
        found = pg.evaluate(MEASURE)
        for kind, items in found.items():
            for it in items:
                kinds[kind][it["key"]].append((url, it.get("text", ""), it.get("cls", "")))

    for kind, groups in kinds.items():
        print(f"\n{kind} — 서로 다른 모양 {len(groups)}가지")
        for key, where in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            sample = where[0]
            print(f"   {len(where):4}개  {key}")
            print(f"          예: {sample[1]!r} {sample[2]!r}  ({sample[0]})")
    b.close()
