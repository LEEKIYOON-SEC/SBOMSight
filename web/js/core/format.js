/**
 * 화면에 보이는 값의 표기.
 *
 * 서버는 시각을 UTC ISO 문자열(`2026-08-22T09:49:37+00:00`)로 준다. 기록으로는
 * 그것이 옳지만 화면에서 읽으라고 내놓을 값은 아니다 — 담당자는 자기 시간대로
 * "어제 오후"인지 "석 달 전"인지를 본다.
 */

/** `2026-08-22 18:49` — 보는 사람의 시간대로. */
export function formatWhen(iso) {
  if (!iso) return '';
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const pad = (n) => String(n).padStart(2, '0');
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} `
       + `${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/** 며칠 지났는가. 값이 없거나 못 읽으면 null — 0으로 채우지 않는다. */
export function daysSince(iso) {
  if (!iso) return null;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return null;
  return Math.max(0, Math.floor((Date.now() - at.getTime()) / 86400000));
}

/**
 * EPSS 확률 → `0.11%`.
 *
 * 백분위는 쓰지 않는다. "확률 0.11% 인데 상위 12%" 라는 두 숫자가 나란히 있으면
 * 어느 쪽을 봐야 하는지 알 수 없고, 실제로 그렇게 물어보셨다.
 */
export function formatProbability(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  const percent = number * 100;
  if (percent > 0 && percent < 0.01) return '<0.01%';
  return `${percent.toFixed(2).replace(/\.?0+$/, '')}%`;
}
