"""화면의 동작이 `Content-Security-Policy` 아래에서 그대로 도는가.

    ./scripts/run-server.sh 로 띄운 뒤
    python3 tests/check-csp.py

**왜 JUnit 이 아니라 여기인가.** CSP 는 브라우저가 지키는 규칙이다. 서버는
머리 한 줄을 보낼 뿐이고, 그 줄 때문에 무엇이 막히는지는 브라우저만 안다.
`SecurityHeaderTest` 는 "머리를 보내는가" 와 "화면에 인라인 스크립트가
없는가" 까지만 볼 수 있다.

**막히면 조용하다.** 단추가 아무 일도 하지 않아도 화면은 200 이고, 화면
시험도 전부 통과한다. 실제로 그랬다 — `img-src 'self'` 가 바탕 CSS 의
고르개 화살표(`data:image/svg+xml`)를 화면 여덟 장에서 막고 있었고,
콘솔을 읽어서야 찾았다.

여기서 보는 것 둘.

1. `data-autosubmit` · `data-confirm` · `data-print` · `data-close` 와
   화면마다의 스크립트가 **실제로 동작하는가**
2. 콘솔에 **CSP 위반이 한 줄도 없는가**
"""
import sys, time
from playwright.sync_api import sync_playwright

B = "https://localhost:8443"
violations = []
console = []
results = []


def ok(label, passed, note=""):
    results.append((label, passed, note))
    print(f"{'  OK  ' if passed else ' FAIL '}{label:<36}{note}")


with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    c = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 950})
    pg = c.new_page()

    def on_console(msg):
        console.append((msg.type, msg.text))
        if "Content Security Policy" in msg.text or "violates the following" in msg.text:
            violations.append(msg.text)
    pg.on("console", on_console)
    pg.on("pageerror", lambda e: console.append(("pageerror", str(e))))

    pg.goto(B + "/login")
    pg.fill('input[name=username]', 'admin')
    pg.fill('input[name=password]', 'devadmin1234')
    pg.click('button[type=submit]')
    pg.wait_for_load_state('networkidle')
    if "/login" in pg.url:
        print("로그인 실패"); sys.exit(1)

    print("── 스크립트 파일이 실제로 내려오는가 ──────────────────────")
    for js in ["app.js", "assets.js", "settings.js", "scan-progress.js", "analysis-dialog.js"]:
        r = pg.request.get(f"{B}/js/{js}")
        ok(f"/js/{js}", r.status == 200 and len(r.body()) > 100,
           f"{r.status} · {len(r.body())}바이트")

    print("\n── 1) 고르개를 고르면 바로 보낸다 (data-autosubmit) ───────")

    def autosubmit(url, selector, value, label):
        pg.goto(B + url, wait_until='domcontentloaded')
        try:
            with pg.expect_navigation(timeout=6000):
                if value is None:
                    pg.check(selector)
                else:
                    pg.select_option(selector, value)
            ok(label, True, pg.url.replace(B, '')[:58])
        except Exception:
            ok(label, False, f"안 넘어감 (여전히 {pg.url.replace(B, '')})")

    autosubmit("/vulns", 'select[name=zone][data-autosubmit]', '2', "취약점 구역 고르개")
    autosubmit("/packages", 'select[name=type][data-autosubmit]', 'rpm', "패키지 유형 고르개")
    autosubmit("/packages", 'select[name=vulnerable][data-autosubmit]', 'true',
               "패키지 `취약점 있는 것만`")
    autosubmit("/actions?tab=analyses", 'select[name=zone][data-autosubmit]', '2',
               "대응 구역 고르개")
    autosubmit("/actions?tab=analyses", 'input[name=includeDone][data-autosubmit]', None,
               "대응 `검토 끝난 것도 보기`")
    autosubmit("/assets/3", 'select[name=zoneId][data-autosubmit]', '3', "자산 구역 옮기기")
    autosubmit("/assets/3", 'select[name=zoneId][data-autosubmit]', '2', "  되돌리기")

    # 구역 색 고르개는 팝업 안에 있다 — 열어야 눌린다.
    pg.goto(B + "/", wait_until='domcontentloaded')
    pg.click('#open-zones')
    time.sleep(0.4)
    try:
        with pg.expect_navigation(timeout=6000):
            pg.eval_on_selector(
                '#zones-dialog input[type=color][data-autosubmit]',
                """el => { el.value = '#123456';
                           el.dispatchEvent(new Event('change', {bubbles: true})); }""")
        ok("구역 색 고르개 (팝업 안)", True, pg.url.replace(B, '')[:58])
    except Exception:
        ok("구역 색 고르개 (팝업 안)", False, "안 넘어감")

    print("\n── 2) 되돌릴 수 없는 것은 묻는다 (data-confirm) ───────────")
    asked = {"n": 0, "text": ""}

    def on_dialog(d):
        asked["n"] += 1
        asked["text"] = d.message
        d.dismiss()          # 취소 — 아무 일도 일어나면 안 된다
    pg.on("dialog", on_dialog)

    pg.goto(B + "/settings", wait_until='domcontentloaded')
    form = pg.query_selector('form[data-confirm]')
    if form:
        asked["n"] = 0
        form.query_selector('button').click()
        time.sleep(1.2)
        ok("설정 — 확인 창이 뜨고 `취소` 로 막힌다", asked["n"] == 1,
           asked["text"].split("\n")[0][:36])
        ok("  줄바꿈이 글자 그대로 남지 않았다", "\\n" not in asked["text"],
           "" if "\\n" not in asked["text"] else f"`\\n` 이 그대로: {asked['text'][:44]!r}")
        ok("  취소했으므로 화면이 그대로다", "/settings" in pg.url, pg.url.replace(B, ''))
    else:
        ok("설정 확인 창", False, "form[data-confirm] 이 없다")

    # 자산 상세의 검사 삭제도 같은 꼴이다
    pg.goto(B + "/assets/3?tab=history", wait_until="domcontentloaded")
    form = pg.query_selector('form[data-confirm]')
    if form:
        asked["n"] = 0
        form.query_selector('button').click()
        time.sleep(1.2)
        ok("자산 상세 — 검사 삭제 확인 창", asked["n"] == 1,
           asked["text"].split("\n")[0][:36])
    else:
        ok("자산 상세 검사 삭제 확인 창", False, "form[data-confirm] 이 없다")

    print("\n── 3) 인쇄 (data-print) ──────────────────────────────────")
    for url, label in [("/reports/zone", "구역 보고서"), ("/reports/scan/1", "자산 보고서")]:
        pg.goto(B + url, wait_until='domcontentloaded')
        pg.evaluate("() => { window.__printed = 0; window.print = () => { window.__printed++; }; }")
        btn = pg.query_selector('[data-print]')
        if btn:
            btn.click()
            time.sleep(0.4)
            ok(f"{label} `인쇄 · PDF`", pg.evaluate("() => window.__printed") == 1)
        else:
            ok(f"{label} 인쇄 단추", False, "없다")

    print("\n── 4) 팝업 열기·닫기 (data-close) ────────────────────────")
    pg.goto(B + "/", wait_until='domcontentloaded')
    pg.click('#open-add')
    time.sleep(0.4)
    ok("자산 `등록` 팝업이 열린다",
       pg.evaluate("() => !!document.querySelector('#add-dialog[open]')"))
    pg.click('#add-dialog [data-close]')
    time.sleep(0.4)
    ok("  팝업이 닫힌다",
       pg.evaluate("() => !document.querySelector('#add-dialog[open]')"))

    pg.goto(B + "/settings", wait_until='domcontentloaded')
    edit = pg.query_selector('.edit-user')
    if edit:
        edit.click()
        time.sleep(0.4)
        ok("설정 계정 `수정` 팝업이 열리고 값이 채워진다", pg.evaluate("""() => {
               const d = document.querySelector('#user-dialog[open]');
               if (!d) return false;
               return d.querySelector('#user-name').textContent.trim().length > 0
                   && d.querySelector('#user-form').action.includes('/settings/users/')
                   && d.querySelector('#user-password').value === '';
           }"""))
        pg.click('#user-dialog [data-close]')
        time.sleep(0.4)
        ok("  팝업이 닫힌다",
           pg.evaluate("() => !document.querySelector('#user-dialog[open]')"))
    else:
        ok("설정 계정 수정 팝업", False, "`.edit-user` 가 없다")

    print("\n── 5) 검토 결과 팝업 (analysis-dialog.js) ────────────────")
    pg.goto(B + "/vulns", wait_until='domcontentloaded')
    link = pg.query_selector('a.analysis-link')
    if link:
        link.click()
        time.sleep(0.5)
        opened = pg.evaluate("() => !!document.querySelector('#analysis-dialog[open]')")
        ok("취약점 표의 `작성` 이 팝업을 연다", opened)
        if opened:
            pg.select_option('#analysis-state', 'NOT_AFFECTED')
            time.sleep(0.4)
            ok("  `해당 없음` → 근거 칸이 열린다", pg.evaluate(
                """() => { const r = document.querySelector('#analysis-justification-row');
                           return !!r && r.offsetParent !== null; }"""))
            pg.select_option('#analysis-state', 'IN_TRIAGE')
            time.sleep(0.4)
            ok("  `검토 중` → 근거 칸이 닫힌다", pg.evaluate(
                """() => { const r = document.querySelector('#analysis-justification-row');
                           return !r || r.offsetParent === null; }"""))
            ok("  고른 것의 뜻 한 줄이 아래에 뜬다", pg.evaluate(
                """() => [...document.querySelectorAll('#analysis-dialog .gloss, '
                        + '#analysis-dialog [id*=gloss]')]
                          .some(g => g.textContent.trim().length > 0)"""))
            pg.click('#analysis-dialog [data-close]')
            time.sleep(0.4)
            ok("  팝업이 닫힌다",
               pg.evaluate("() => !document.querySelector('#analysis-dialog[open]')"))
    else:
        ok("취약점 표의 `작성`", False, "`a.analysis-link` 가 없다")

    print("\n── 6) 구역 접기 (assets.js) ──────────────────────────────")
    pg.goto(B + "/", wait_until='domcontentloaded')
    fold = pg.query_selector('.zone-fold')
    if fold:
        fold.click()
        time.sleep(0.4)
        folded = pg.evaluate("() => !!document.querySelector('tbody.zone-group.folded')")
        ok("구역 머리를 눌러 접힌다", folded)
        if folded:
            fold.click()
            time.sleep(0.4)
            ok("  다시 눌러 펼쳐진다",
               pg.evaluate("() => !document.querySelector('tbody.zone-group.folded')"))
    else:
        ok("구역 접기", False, "`.zone-fold` 가 없다")

    print("\n── 7) 검사 진행 표시 (scan-progress.js) ──────────────────")
    errs_before = len([1 for t, _ in console if t == 'pageerror'])
    pg.goto(B + "/assets/3", wait_until='networkidle')
    time.sleep(1)
    ok("진행 표시가 없는 자산에서 오류 없음",
       len([1 for t, _ in console if t == 'pageerror']) == errs_before)

    print("\n── CSP 위반 · 콘솔 오류 ──────────────────────────────────")
    errs = [(t, m) for t, m in console if t in ('error', 'pageerror')]
    ok("CSP 위반 0건", not violations,
       "" if not violations else f"{len(violations)}건: {violations[0][:90]}")
    ok("콘솔 오류 0건", not errs,
       "" if not errs else f"{len(errs)}건: {errs[0][1][:90]}")

    b.close()

bad = [r for r in results if not r[1]]
print(f"\n{'='*70}\n확인 {len(results)}개 · 어긋난 것 {len(bad)}개")
for label, _, note in bad:
    print(f"  · {label}  {note}")
sys.exit(1 if bad else 0)
