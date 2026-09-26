/* 화면 전체가 쓰는 다섯 가지 동작.
 *
 * **왜 여기 있는가.** 앞서 1–4 는 화면에 `onchange="this.form.submit()"` ·
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
      // `submit()` 는 아래 5) 의 submit 이벤트를 거치지 않는다 — 여기서 직접 뺀다.
      var off = dropEmpty(el.form);
      if (off.length && nothingLeft(el.form)) {
        restore(off);
        location.assign(bare(el.form));
        return;
      }
      el.form.submit();
      restore(off);
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

  /* 5) 필터 폼은 빈 칸을 주소에 싣지 않는다 — `<form method="get">`
   *
   * 브라우저는 고르지 않은 칸도 이름을 적어 보낸다. 찾기 한 번에 주소가
   * `/vulns?zone=&group=item&q=&severity=&kev=&fixable=` 가 됐다. 화면 안의
   * 링크는 서버가 고른 것만 적어 만드는데(VulnQuery.Links), 폼으로 보낸 주소만
   * 이 꼴이었다 — 그 주소가 결재 문서에 붙고 옆자리에 전달된다.
   *
   * 빈 칸을 잠시 꺼 두고(disabled) 보낸다. 꺼 둔 칸은 보내지 않는다. 보낼
   * 값은 보내는 그 순간에 정해지므로 곧바로 되살린다 — 되살리지 않으면 뒤로
   * 가기로 돌아온 화면(브라우저가 쥐고 있던 그대로)에서 칸이 죽어 있다.
   * 확인을 묻다가 취소한 폼(2)은 보내지 않으므로 손대지 않는다.
   *
   * 칸이 전부 비었으면 폼으로 보내지 않고 그 주소로 간다 — 보내면 `?` 하나만
   * 붙은 주소(`/settings/audit?`)가 된다. */
  document.addEventListener('submit', function (e) {
    if (e.defaultPrevented) {
      return;
    }
    var form = e.target;
    var off = dropEmpty(form);
    if (!off.length) {
      return;
    }
    if (nothingLeft(form)) {
      e.preventDefault();
      restore(off);
      location.assign(bare(form));
      return;
    }
    setTimeout(function () { restore(off); }, 0);
  });

  /* 꺼 두고 나니 보낼 칸이 하나도 없는가. */
  function nothingLeft(form) {
    return !new FormData(form).keys().next().value;
  }

  /* 폼이 가는 주소에서 묻는 값을 뗀 것. `action` 이 없는 폼은 지금 주소로
   * 가므로, 떼지 않으면 지금 걸린 필터가 그대로 남는다.
   *
   * `form.action` 을 읽지 않는다 — 칸 이름이 `action` 이면(감사 로그의 행위
   * 필터) 그 칸이 대신 나온다. 띄운 앱에서 `/settings/[object
   * HTMLSelectElement]` 로 가 400 이 났다. 속성을 직접 읽는다. */
  function bare(form) {
    var url = new URL(form.getAttribute('action') || location.href, location.href);
    url.search = '';
    url.hash = '';
    return url.href;
  }

  function dropEmpty(form) {
    var off = [];
    if ((form.getAttribute('method') || '').toLowerCase() !== 'get') {
      return off;
    }
    Array.prototype.forEach.call(form.elements, function (el) {
      var field = el.tagName === 'SELECT' || (el.tagName === 'INPUT'
          && el.type !== 'checkbox' && el.type !== 'radio' && el.type !== 'submit');
      if (field && el.name && !el.disabled && el.value === '') {
        el.disabled = true;
        off.push(el);
      }
    });
    return off;
  }

  function restore(off) {
    off.forEach(function (el) { el.disabled = false; });
  }
})();
