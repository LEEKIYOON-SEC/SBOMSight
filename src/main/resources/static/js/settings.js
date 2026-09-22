/* 설정 — 계정 `수정` 팝업.
 *
 * 화면에서 떼어 냈다(CSP). 팝업 닫기는 `app.js` 가 맡는다. */
(function () {
  const dialog = document.querySelector('#user-dialog');
  if (!dialog) return;
  const form = dialog.querySelector('#user-form');

  document.addEventListener('click', function (e) {
    const button = e.target.closest('.edit-user');
    if (button) {
      // 주소는 계정마다 다르다. 폼 하나를 옮겨 쓴다.
      form.action = '/settings/users/' + encodeURIComponent(button.dataset.username);
      dialog.querySelector('#user-name').textContent = button.dataset.username;
      dialog.querySelector('#user-display').value = button.dataset.display || '';
      dialog.querySelector('#user-role').value = button.dataset.role;
      dialog.querySelector('#user-enabled').checked = button.dataset.enabled === 'true';
      // 열 때마다 비운다. 남아 있으면 이름만 고치려다 비밀번호까지 바뀐다.
      dialog.querySelector('#user-password').value = '';
      dialog.showModal();
      return;
    }
  });
})();
