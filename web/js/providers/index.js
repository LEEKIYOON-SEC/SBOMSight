/**
 * 스캔 제공자 선택.
 *
 * 같은 프론트엔드가 두 환경에서 돈다:
 *   - 로컬 PC 서버  → live-api.js  (진짜 Grype 서브프로세스)
 *   - GitHub Pages → browser-engine.js (브라우저 매칭 엔진, M6에서 추가)
 *
 * 판별은 정적 배포 여부로 한다. `window.SBOMSIGHT_MODE`가 지정되어 있으면
 * 그것을 따르고, 없으면 /api/health 로 로컬 서버 존재를 확인한다.
 */

import { liveApiProvider } from './live-api.js';

let cached = null;

async function detectMode() {
  if (window.SBOMSIGHT_MODE) return window.SBOMSIGHT_MODE;
  try {
    const response = await fetch('/api/health', { method: 'GET' });
    if (response.ok) return 'live';
  } catch { /* 정적 호스팅이면 여기로 온다 */ }
  return 'demo';
}

export async function getProvider() {
  if (cached) return cached;
  const mode = await detectMode();

  if (mode === 'demo') {
    try {
      const { browserEngineProvider } = await import('./browser-engine.js');
      cached = browserEngineProvider;
      return cached;
    } catch (error) {
      // M6 이전이거나 데모 데이터가 없는 경우. 조용히 실패하지 않고 알린다.
      console.warn('브라우저 엔진을 불러오지 못했습니다:', error);
      cached = { ...liveApiProvider, unavailable: true };
      return cached;
    }
  }

  cached = liveApiProvider;
  return cached;
}
