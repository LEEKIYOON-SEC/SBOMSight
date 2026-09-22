/* 검토 결과 팝업 — 고른 것에 따라 칸을 열고 닫고, 뜻 한 줄을 쓴다.
 *
 * 화면에서 떼어 냈다(CSP). 팝업 닫기는 `app.js` 가 맡는다.
 * 이 조각은 취약점 화면과 대응 화면이 함께 쓴다. */
(function () {
  const dialog = document.querySelector('#analysis-dialog');
  if (!dialog) return;

  const state = dialog.querySelector('#analysis-state');
  const response = dialog.querySelector('#analysis-response');
  const justificationRow = dialog.querySelector('#analysis-justification-row');
  const reviewRow = dialog.querySelector('#analysis-review-row');
  const review = dialog.querySelector('#analysis-review');
  const justification = dialog.querySelector('#analysis-justification');

  // 고른 것의 뜻 한 줄을 아래에 쓴다. 값은 서버가 그린 option 에 들어 있다 —
  // 여기서 말을 짓지 않는다. 두 벌이 되면 화면 말만 바뀌는 날이 온다.
  function gloss(select) {
    const target = document.getElementById(select.dataset.gloss);
    if (!target) return;
    const picked = select.options[select.selectedIndex];
    target.textContent = picked ? (picked.dataset.gloss || '') : '';
  }

  function sync() {
    const pickedState = state.options[state.selectedIndex];
    const needsJustification = pickedState
            && pickedState.dataset.needsJustification === 'true';
    justificationRow.hidden = !needsJustification;
    justification.required = needsJustification;

    const pickedResponse = response.options[response.selectedIndex];
    const needsReview = pickedResponse && pickedResponse.dataset.needsReview === 'true';
    reviewRow.hidden = !needsReview;
    review.required = needsReview;

    gloss(state);
    gloss(response);
  }

  state.addEventListener('change', sync);
  response.addEventListener('change', sync);

  document.addEventListener('click', function (e) {
    const link = e.target.closest('.analysis-link');
    if (link) {
      e.preventDefault();
      dialog.querySelector('#analysis-asset').value = link.dataset.asset;
      dialog.querySelector('#analysis-cve').value = link.dataset.cve;
      dialog.querySelector('#analysis-pkg').value = link.dataset.pkg;
      dialog.querySelector('#analysis-what').textContent =
              link.dataset.label + ' · ' + link.dataset.pkg;

      // 이미 적어 둔 것이 있으면 그 값에서 시작한다. 빈 칸에서 시작하면
      // 한 칸만 고치려던 사람이 나머지를 지우게 된다.
      state.value = link.dataset.state || 'NOT_SET';
      justification.value = link.dataset.justification || '';
      response.value = link.dataset.response || '';
      review.value = link.dataset.review || '';
      dialog.querySelector('#analysis-note').value = link.dataset.note || '';
      dialog.querySelector('#analysis-control').value = link.dataset.control || '';
      dialog.querySelector('#analysis-doc').value = link.dataset.doc || '';

      // 으뜸 단추의 글자는 목록의 링크와 같아야 한다 — 목록에서 `수정` 을
      // 눌렀는데 팝업이 `작성` 이라고 하면 새로 쓰는 것으로 읽힌다.
      dialog.querySelector('#analysis-submit').textContent =
              link.dataset.exists === 'true' ? '수정' : '작성';

      sync();
      dialog.showModal();
      return;
    }
  });

  sync();
})();
