/**
 * 유휴 로그아웃 — 쓰고 있지 않으면 끊는다.
 *
 * 이 화면들은 "어느 서버에 무엇이 열려 있는가"를 그대로 보여 준다. 자리를 비운
 * 사이 열려 있는 창은 그 자체가 새는 구멍이다.
 *
 * **판단은 서버가 한다.** 서버는 마지막 요청 시각으로 유휴를 재고, 창이 넘어간
 * 뒤에는 무엇을 눌러도 401 이 온다. 여기서 하는 일은 두 가지다.
 *
 * 1. **끊긴 것을 눈에 보이게 한다.** 아무 요청도 안 하면 서버가 세션을 지워도
 *    화면은 로그인한 채로 남아 있다. 눌러 보기 전까지는 끊긴 줄 모른다.
 * 2. **읽고 있는 중에 끊기지 않게 한다.** 긴 표를 십 분 넘게 훑는 동안에는
 *    요청이 한 번도 안 나간다. 조작이 있었으면 살아 있다고 알린다.
 *
 * 조작으로 세는 것은 누르기·타이핑·스크롤이다. 마우스 움직임은 넣지 않았다 —
 * 책상에 놓인 마우스가 한 번 흔들리는 것으로 세션이 무한정 연장된다.
 */

/** 유휴를 확인하는 주기. 만료 시점보다 이만큼 늦게 반응할 수 있다. */
const CHECK_MS = 15_000;

/** 조작이 있었을 때 서버에 알리는 최소 간격. 서버 쪽 기록 주기(30초)의 두 배. */
const PING_MS = 60_000;

const ACTIVITY = ['pointerdown', 'keydown', 'wheel', 'scroll', 'touchstart'];

/**
 * @param {number} minutes 서버가 알려 준 유휴 만료(분). 0 이하면 걸지 않는다.
 * @param {object} [hooks] 시험용 갈고리. 실제 화면에서는 쓰지 않는다.
 */
export function watchIdle(minutes, hooks = {}) {
  const limit = Number(minutes) * 60_000;
  if (!(limit > 0)) return null;

  const now = hooks.now || (() => Date.now());
  const send = hooks.fetch || ((path, options) => fetch(path, options).catch(() => {}));
  const leave = hooks.leave || ((url) => window.location.replace(url));

  let lastActive = now();
  let lastPing = now();
  let finished = false;

  const mark = () => { lastActive = now(); };
  for (const type of ACTIVITY) {
    window.addEventListener(type, mark, { passive: true, capture: true });
  }
  // 다른 창에 갔다가 돌아온 것도 조작이다. 돌아온 순간 이미 지났으면 아래
  // 확인이 바로 잡아낸다.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) mark();
    check();
  });

  async function check() {
    if (finished) return;
    const idle = now() - lastActive;

    if (idle >= limit) {
      finished = true;
      // 서버 세션도 같이 지운다. 화면만 로그인으로 보내고 세션을 남겨 두면,
      // 쿠키가 살아 있는 동안 뒤로 가기 한 번으로 되돌아온다.
      await send('api/auth/logout', { method: 'POST' });
      leave('login.html?expired=1');
      return;
    }

    // 조작이 있었는데 그 뒤로 서버에 나간 요청이 없으면, 읽고 있는 도중에
    // 서버 쪽 시계만 흘러간다. 조작이 있었을 때만 알린다 — 무조건 보내면
    // 열어 둔 창 하나가 세션을 영원히 살려 둔다.
    if (lastActive > lastPing && now() - lastPing >= PING_MS) {
      lastPing = now();
      await send('api/auth/state');
    }
  }

  const timer = setInterval(check, hooks.interval || CHECK_MS);
  return { check, stop: () => { finished = true; clearInterval(timer); } };
}
