/* 검사 진행 표시 — 자산 상세의 `개요` 탭.
 *
 * 화면에서 떼어 냈다(CSP). `#progress` 가 없는 화면에서는 아무것도 하지
 * 않으므로 어느 탭에서 불려도 안전하다. */
// 검사가 도는 동안만 물어본다. 끝나면 스스로 멈춘다.
//
// 밀어 주는 방식(SSE·WebSocket)을 쓰지 않는 이유: 연결이 하나 더 생기고
// 세션 만료·프록시 설정이 전부 변수가 된다. 몇 분짜리 작업의 진행을
// 보여 주는 데 그만한 것을 들일 이유가 없다.
(function () {
  const box = document.querySelector('#progress');
  if (!box) return;
  const id = box.dataset.scan;
  const el = (r) => box.querySelector('[data-role="' + r + '"]');

  function time(sec) {
    const m = Math.floor(sec / 60), s = sec % 60;
    return m > 0 ? m + '분 ' + s + '초' : s + '초';
  }

  function draw(p) {
    el('title').textContent = p.failed ? '검사 실패'
                            : p.done   ? '검사 완료'
                                       : p.stageLabel;
    el('subtitle').textContent = p.failed ? (p.error || '') : p.stageDetail;
    el('elapsed').textContent = time(p.elapsedSeconds);

    const icon = el('icon');
    icon.className = p.failed ? 'mark critical' : p.done ? 'done-mark' : 'spinner';

    if (p.done) {
      const open = el('open');
      open.href = '/vulns?scan=' + p.scanId;
      open.hidden = false;
    }
    box.classList.toggle('failed', !!p.failed);

    el('steps').innerHTML = p.steps.map(function (s) {
      return '<div class="step ' + s.state + '">'
           +   '<div class="rail"><i></i><span></span></div>'
           +   '<div class="name"></div><div class="detail num"></div>'
           + '</div>';
    }).join('');
    // 값은 textContent 로만 넣는다. 서버가 준 문자열에 자산 이름과 오류
    // 문구가 섞여 들어오므로 innerHTML 로 붙이면 그 자리가 구멍이 된다.
    box.querySelectorAll('.step').forEach(function (node, i) {
      node.querySelector('.name').textContent = p.steps[i].label;
      node.querySelector('.detail').textContent = p.steps[i].detail || '';
    });
  }

  let stop = false;
  function poll() {
    if (stop) return;
    fetch('/scans/' + id + '/status', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (p) {
        draw(p);
        if (p.running) { setTimeout(poll, 2000); return; }
        stop = true;
        // 끝났으면 이력·조치·머리줄이 전부 바뀐다. 통째로 다시 그린다.
        setTimeout(function () { location.reload(); }, 1200);
      })
      .catch(function () {
        // 서버가 잠깐 대답하지 않아도 포기하지 않는다. 다만 간격을 늘린다.
        setTimeout(poll, 5000);
      });
  }
  poll();
})();
