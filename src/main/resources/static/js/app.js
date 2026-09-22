/* 화면 전체가 쓰는 네 가지 동작.
 *
 * **왜 여기 있는가.** 앞서 이 넷은 화면에 `onchange="this.form.submit()"` ·
 * `onsubmit="return confirm(…)"` · `onclick="window.print()"` 로 열일곱 군데
 * 흩어져 있었다. 그 꼴이 하나라도 남아 있으면
 * `Content-Security-Policy` 에 `script-src-attr 'unsafe-inline'` 을 넣어야
 * 하고, 그것을 넣는 순간 **CSP 가 막으려던 것을 그대로 허용한다** — 끼워
 * 넣어진 `onerror=` 도 함께 돈다.
 *
 * 그래서 화면은 `data-…` 로 **무엇을 할지만** 적고, 하는 일은 여기 한 곳에
 * 둔다. 같은 동작이 화면마다 조금씩 다르게 놀던 것도 함께 사라진다.
 */
(function () {
  'use strict';

  /* 1) 고르개를 고르면 바로 보낸다 — `data-autosubmit`
   *
   * 거르개 옆에 `적용` 단추를 두지 않는다. 고르고 나서 한 번 더 눌러야 하면
   * 고른 값과 보이는 목록이 어긋난 순간이 생긴다. */
  document.addEventListener('change', function (e) {
    var el = e.target.closest('[data-autosubmit]');
    if (el && el.form) {
      el.form.submit();
    }
  });

  /* 2) 되돌릴 수 없는 것은 한 번 묻는다 — `data-confirm="문구"`
   *
   * 문구는 화면이 정한다. 무엇이 함께 사라지는지는 그 자리마다 다르고,
   * 여기서 지어내면 "정말 지울까요?" 한 마디가 되어 아무것도 알려 주지
   * 못한다.
   *
   * 속성에 적은 `\n` 두 글자는 줄바꿈으로 바꾼다 — HTML 속성에 진짜
   * 줄바꿈을 넣으면 화면 소스가 읽기 어려워진다. */
  document.addEventListener('submit', function (e) {
    var form = e.target.closest('[data-confirm]');
    if (form && !window.confirm(form.dataset.confirm.replace(/\\n/g, '\n'))) {
      e.preventDefault();
    }
  }, true);

  /* 3) 인쇄 — `data-print`
   *
   * 보고서는 결재로 올라간다. 브라우저 메뉴를 찾아 들어가지 않게 화면에
   * 단추를 둔다. */
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-print]')) {
      window.print();
    }
  });

  /* 4) 팝업 닫기 — `data-close`
   *
   * 여는 것은 화면마다 다르지만 닫는 것은 하나다. `<dialog>` 라 Esc 는
   * 브라우저가 처리한다. */
  document.addEventListener('click', function (e) {
    var close = e.target.closest('[data-close]');
    if (close) {
      var dialog = close.closest('dialog');
      if (dialog) {
        dialog.close();
      }
    }
  });
})();
