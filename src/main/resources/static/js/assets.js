/* 자산 목록 — 팝업 열기와 구역 접기.
 *
 * 화면에서 떼어 냈다. 인라인 <script> 가 하나라도 남아 있으면
 * `Content-Security-Policy` 에 `script-src 'unsafe-inline'` 을 넣어야 하고,
 * 그것을 넣는 순간 CSP 가 막으려던 것을 그대로 허용한다.
 *
 * 팝업 닫기(`[data-close]`)는 `app.js` 가 화면 전체에서 맡는다. */
// 팝업 열기. 닫기와 Esc 는 각각 app.js 와 브라우저가 맡는다.
document.addEventListener('click', function (e) {
  if (e.target.closest('#open-add')) {
    document.querySelector('#add-dialog').showModal();
    return;
  }
  if (e.target.closest('#open-zones')) {
    document.querySelector('#zones-dialog').showModal();
    return;
  }
});

// 구역 접기.
//
// 접은 것은 **주소에 넣지 않는다.** 주소에 넣으면 그 링크가 결재 문서에
// 붙고, 받은 사람은 접힌 목록을 전체라고 읽는다. 이 브라우저의 이 세션
// 에만 남긴다 — 다음에 열면 다시 전부 펼쳐져 있다.
(function () {
  const table = document.querySelector('.asset-table');
  if (!table) return;
  const KEY = 'sbomsight.folded-zones';
  const groups = Array.from(table.querySelectorAll('tbody.zone-group'));
  const all = document.querySelector('#fold-all');

  let folded = new Set();
  try { folded = new Set(JSON.parse(sessionStorage.getItem(KEY) || '[]')); } catch (e) { }
  // 구역을 골라 놓았으면 접힌 것을 무시하고 펼친다 — 한 구역만 남은
  // 목록이 접혀 있으면 걸러 놓고 빈 화면을 보게 된다.
  if (table.dataset.zonePicked === 'true') { folded = new Set(); }

  function save() {
    try { sessionStorage.setItem(KEY, JSON.stringify(Array.from(folded))); } catch (e) { }
  }

  function anyOpen() {
    return groups.some(function (g) { return !folded.has(g.dataset.zone); });
  }

  function draw() {
    groups.forEach(function (g) {
      const off = folded.has(g.dataset.zone);
      g.classList.toggle('folded', off);
      const b = g.querySelector('.zone-fold');
      if (!b) return;
      b.textContent = off ? '▸' : '▾';
      b.setAttribute('aria-expanded', off ? 'false' : 'true');
      const name = g.querySelector('.zone-head b');
      b.title = (name ? name.textContent + ' ' : '') + (off ? '펼치기' : '접기');
    });
    if (all) { all.textContent = anyOpen() ? '모두 접기' : '모두 펼치기'; }
  }

  table.addEventListener('click', function (e) {
    const b = e.target.closest('.zone-fold');
    if (!b) return;
    const id = b.closest('tbody.zone-group').dataset.zone;
    if (folded.has(id)) { folded.delete(id); } else { folded.add(id); }
    save();
    draw();
  });

  if (all) {
    all.addEventListener('click', function () {
      folded = anyOpen()
              ? new Set(groups.map(function (g) { return g.dataset.zone; }))
              : new Set();
      save();
      draw();
    });
  }

  draw();
})();

// 운영 종료한 자산까지 보기. 주소에 남아야 새로고침해도 유지된다.
const archived = document.querySelector('#archived-toggle');
if (archived) {
  archived.addEventListener('change', function () {
    const url = new URL(location.href);
    if (archived.checked) { url.searchParams.set('archived', 'true'); }
    else { url.searchParams.delete('archived'); }
    location.href = url.toString();
  });
}
