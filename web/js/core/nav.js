/**
 * 상단 바 — 페이지마다 손으로 복사해 두던 것을 한 곳으로 모았다.
 *
 * 네 페이지에 같은 마크업이 흩어져 있으면 메뉴 하나를 바꿀 때마다 네 곳을
 * 고쳐야 하고, 실제로 한 곳이 빠져 예전 메뉴가 남아 있었다.
 *
 * 로그인한 사람과 권한도 여기서 보여 준다. 지금 누구로 보고 있는지 모른 채
 * 조작하다가 "관리자만 할 수 있습니다"를 만나면 이유를 알 수 없다.
 */

import { esc } from './ui.js';
import { watchIdle } from './idle.js';

// 스캔은 탭이 아니다. SBOM 은 **자산에 올리는 것**이고, 스캔 결과는 그 자산의
// 것이다. 탭으로 두면 "어느 서버 것인지 나중에 정하는" 길이 열리고, 실제로
// 그래서 어디에도 속하지 않는 결과가 쌓였다.
const LINKS = [
  { href: 'index.html', label: '자산' },
  { href: 'settings.html', label: '설정', adminOnly: true },
];

async function authState() {
  try {
    const response = await fetch('api/auth/state');
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null; // 정적 배포(Pages)에는 인증이 없다.
  }
}

export async function mountTopbar(currentHref) {
  const header = document.querySelector('.topbar');
  if (!header) return null;

  const state = await authState();
  const role = state?.role || '';
  const links = LINKS.filter((link) => !link.adminOnly || role === 'admin');

  header.innerHTML = `
    <div class="brand"><a href="index.html">SBOMSight</a><small>SBOM 기반 취약점 대응 검토</small></div>
    <div class="spacer"></div>
    <nav>
      ${links.map((link) => `<a href="${link.href}"${
        link.href === currentHref ? ' aria-current="page"' : ''
      }>${esc(link.label)}</a>`).join('\n      ')}
    </nav>
    ${state?.authenticated ? `
      <div class="whoami">
        <span class="who">${esc(state.username)}</span>
        <span class="role ${role === 'admin' ? 'admin' : ''}">${role === 'admin' ? '관리자' : '조회'}</span>
        <button type="button" class="btn small" id="logout">로그아웃</button>
      </div>` : ''}`;

  const logout = header.querySelector('#logout');
  if (logout) {
    logout.addEventListener('click', async () => {
      await fetch('api/auth/logout', { method: 'POST' });
      window.location.href = 'login.html';
    });
  }

  // 자리를 비우면 끊는다. 만료까지 몇 분인지는 서버가 정하고 알려 준다 —
  // 화면에 숫자를 박아 두면 설정을 바꿨을 때 두 곳이 어긋난다.
  if (state?.authenticated) watchIdle(state.idle_minutes);

  return state;
}
