/**
 * 스캔 제공자 선택.
 *
 * 같은 프론트엔드가 두 환경에서 돈다:
 *   - 로컬 PC 서버  → live-api.js       진짜 Syft/Grype가 도는 실 제품
 *   - GitHub Pages → static-results.js  실 PC에서 뽑아 둔 결과를 그대로 전시
 *
 * 한때 브라우저 안에 매칭 엔진을 두어 Pages에서도 "스캔"이 되게 했지만
 * 걷어냈다. Grype의 매칭은 배포판 네임스페이스·CPE·상위 소스패키지 해석까지
 * 얽혀 있어서 두 번째 구현은 반드시 갈라지고, 갈라진 쪽은 조용히 틀린 판정을
 * 낸다(Debian 13 advisory를 Debian 11 패키지에 적용하는 식으로). 취약점
 * 판정은 한 벌만 존재해야 한다 — 진짜 Grype.
 *
 * 판별은 정적 배포 여부로 한다. `window.SBOMSIGHT_MODE`가 지정되어 있으면
 * 그것을 따르고, 없으면 api/health로 로컬 서버 존재를 확인한다.
 */

import { liveApiProvider } from './live-api.js';

let cached = null;

async function detectMode() {
  if (window.SBOMSIGHT_MODE) return window.SBOMSIGHT_MODE;
  try {
    const response = await fetch('api/health', { method: 'GET' });
    if (response.ok) return 'live';
  } catch { /* 정적 호스팅이면 여기로 온다 */ }
  return 'static';
}

export async function getProvider() {
  if (cached) return cached;
  const mode = await detectMode();

  if (mode === 'static' || mode === 'demo') {
    const { staticResultsProvider } = await import('./static-results.js');
    cached = staticResultsProvider;
    return cached;
  }

  cached = liveApiProvider;
  return cached;
}
