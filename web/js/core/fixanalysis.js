/**
 * [로컬 전용] 설치 버전 ↔ Fixed Version 비교 판정 — core/fixanalysis.py 의 동형.
 *
 * 여기서 나오는 값은 우리 환경에 대한 사실이므로 AI에 전달하지 않는다.
 * 판단할 수 없으면 'unknown'으로 남긴다 — "취약하지 않음"이라고 답하면
 * 그 취약점은 조용히 사라진다.
 */

import { compare, comparatorFor, satisfies, versionGap } from './versioning.js';

const ternary = (value) => (value === null || value === undefined ? 'unknown' : (value ? 'true' : 'false'));

function pickComparator(installed, advisory) {
  for (const candidate of [advisory.advisory_ecosystem, installed.type]) {
    const name = comparatorFor(candidate);
    if (name !== 'generic') return name;
  }
  return 'generic';
}

export function analyzeFix(installed, advisory, { detectedByScanner = true } = {}) {
  const comparator = pickComparator(installed, advisory);
  const version = installed.version;
  const fixed = advisory.fixed_version || '';
  const reasons = [];

  // --- 취약 여부 -----------------------------------------------------------
  let vulnerable = null;
  if (advisory.affected_version_range) {
    vulnerable = satisfies(version, advisory.affected_version_range, comparator);
    if (vulnerable === null) {
      reasons.push(`영향 버전범위 '${advisory.affected_version_range}'를 ${comparator} 규칙으로 해석할 수 없음`);
    }
  } else if (fixed) {
    const rc = compare(version, fixed, comparator);
    if (rc === null) reasons.push(`설치 버전 '${version}'과 수정 버전 '${fixed}'를 ${comparator} 규칙으로 비교할 수 없음`);
    else vulnerable = rc < 0;
  } else {
    reasons.push('advisory에 영향 버전범위도 수정 버전도 없음');
  }

  if (vulnerable === false && detectedByScanner) {
    reasons.push('스캐너는 취약으로 탐지했으나 버전 비교상으로는 영향 범위 밖 — 확인 필요');
  }

  // --- 업데이트 가능 여부 ---------------------------------------------------
  let updateAvailable;
  if (!fixed) {
    updateAvailable = false;
    reasons.push('공개된 수정 버전이 없어 업데이트 대상이 존재하지 않음');
  } else {
    const rc = compare(version, fixed, comparator);
    updateAvailable = rc === null ? null : rc < 0;
  }

  // --- 수정 상태 ------------------------------------------------------------
  let fixState = advisory.fix_state && advisory.fix_state !== 'unknown'
    ? advisory.fix_state
    : (fixed ? 'fixed_available' : 'unknown');

  return {
    installed_version: version,
    fixed_version: fixed,
    comparator,
    is_vulnerable: ternary(vulnerable),
    update_available: ternary(updateAvailable),
    fix_state: fixState,
    version_gap: fixed ? versionGap(version, fixed, comparator) : 'unknown',
    reason: reasons.join('; '),
  };
}
