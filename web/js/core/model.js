/**
 * 공용 상수와 표시 라벨.
 *
 * 여기에는 판정 로직이 없다 — 취약 여부도, 우선순위도 서버가 이미 정해서
 * 내려준다. 이 파일이 하는 일은 그 값을 사람이 읽을 문자열로 옮기는 것뿐이다.
 * 문자열 리터럴은 core/models.py 의 열거형 값과 일치해야 한다.
 */

import { formatProbability } from './format.js';

export const PRIORITIES = ['P0', 'P1', 'P2', 'P3'];

/**
 * 화면에 보이는 것은 이 문구뿐이다. `P0`·`P1` 같은 코드는 **표시하지 않는다.**
 *
 * 코드를 보여 주면 읽는 사람이 매번 "P1이 뭐였지"를 되짚어야 하고, 코드에는
 * 뜻이 없으므로 되짚을 근거도 화면에 없다. 내부 값은 정렬·필터의 축으로만 남는다.
 */
export const PRIORITY_LABEL = {
  P0: '즉시 검토',
  P1: '우선 검토',
  P2: '계획 검토',
  P3: '모니터링',
};

export const TERNARY_LABEL = { true: '예', false: '아니오', unknown: '미확인' };

export const FIX_STATE_LABEL = {
  fixed_available: '수정 버전 있음',
  not_fixed: '미수정',
  wont_fix: '수정 예정 없음',
  unknown: '미확인',
};

export const MATURITY_LABEL = {
  weaponized: '무기화 (즉시 사용 가능한 공격 도구 공개)',
  public_poc: '공개 PoC',
  none: '확인된 공개 exploit 없음',
  unknown: '미확인',
};

export const EXPLOIT_SOURCE_LABEL = {
  exploit_db: 'Exploit-DB',
  metasploit: 'Metasploit',
  github_poc: 'GitHub PoC',
  nuclei: 'Nuclei 템플릿',
};

export const SEVERITY_LABEL = {
  critical: 'Critical', high: 'High', medium: 'Medium',
  low: 'Low', negligible: 'Negligible', unknown: '미확인',
};

/** 판정에 쓸 데이터를 확보하지 못한 항목들. 값이 낮은 것과 구분한다. */
export const UNKNOWN_FLAGS = new Set([
  'unknown_epss', 'unknown_exploit', 'unknown_kev', 'no_cvss',
]);

/**
 * 플래그 표시 문구. rules/priority.json 의 label·note 와 같은 내용을 담되,
 * 정책 파일을 받아오지 못하는 상황(데모 모드 등)에서도 화면이 원시 키를
 * 노출하지 않도록 프론트엔드에도 둔다.
 */
export const FLAG_LABEL = {
  no_fix_available: ['수정 버전 없음', '패치로 해소할 수 없으므로 완화 방안 검토가 필요합니다'],
  update_available: ['업데이트 가능', '상위 버전으로 갱신할 수 있습니다'],
  unknown_epss: ['악용 예측 미확인', 'EPSS 데이터를 확보하지 못해 악용 예측이 판정에 반영되지 않았습니다'],
  unknown_exploit: ['공격코드 공개 여부 미확인', '공개 공격코드 여부를 확인하지 못해 판정에 반영되지 않았습니다'],
  unknown_kev: ['실제 악용 여부 미확인', 'CISA KEV 카탈로그를 조회하지 못해 판정에 반영되지 않았습니다'],
  no_cvss: ['심각도 미확인', 'CVSS 점수를 확보하지 못해 심각도 기반 판정이 적용되지 않았습니다'],
  stale_snapshot: ['위협정보 오래됨', 'EPSS · KEV 스냅샷이 기준일보다 오래되어 최신 데이터로 다시 판정하는 편이 좋습니다'],
};

export function describeFlag(name) {
  const [label, note] = FLAG_LABEL[name] || [name, ''];
  return { name, label, note };
}

/**
 * 선택 키 — core/models.py 의 `Finding.key` 와 같은 형식이어야 한다.
 * 서버가 이 문자열로 항목을 되찾으므로 한 글자라도 다르면 선택이 먹지 않는다.
 *
 * 설치 패키지명과 설치 버전이 들어 있는 **내부 문자열**이다. 브라우저와 로컬
 * 서버 사이에서만 오가며, AI로 나가는 VulnFact 에는 등장하지 않는다.
 */
export function findingKey(f) {
  return [
    f.intel?.cve ?? '',
    f.installed?.name ?? '',
    f.installed?.version ?? '',
    f.installed?.purl ?? '',
  ].join('|');
}

export function priorityRank(p) {
  const idx = PRIORITIES.indexOf(p);
  return idx < 0 ? 9 : idx;
}

/** 리포트·표 정렬: 우선순위 → CVSS 내림차순 → EPSS 내림차순 → CVE. */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const pa = priorityRank(a.verdict?.priority);
    const pb = priorityRank(b.verdict?.priority);
    if (pa !== pb) return pa - pb;
    const ca = a.intel?.cvss_score ?? 0;
    const cb = b.intel?.cvss_score ?? 0;
    if (ca !== cb) return cb - ca;
    const ea = a.intel?.epss ?? 0;
    const eb = b.intel?.epss ?? 0;
    if (ea !== eb) return eb - ea;
    return (a.intel?.cve || '').localeCompare(b.intel?.cve || '');
  });
}

export function summarize(findings) {
  const byPriority = { P0: 0, P1: 0, P2: 0, P3: 0 };
  let updatable = 0, noFix = 0, kev = 0, exploit = 0;
  const packages = new Set();

  for (const f of findings) {
    const p = f.verdict?.priority;
    if (p in byPriority) byPriority[p] += 1;
    if (f.fix?.update_available === 'true') updatable += 1;
    if (f.verdict?.flags?.includes('no_fix_available')) noFix += 1;
    if (f.intel?.kev === 'true') kev += 1;
    if (f.intel?.exploit_available === 'true') exploit += 1;
    if (f.installed?.name) packages.add(f.installed.name);
  }

  return {
    total: findings.length,
    by_priority: byPriority,
    update_available: updatable,
    no_fix_available: noFix,
    kev_listed: kev,
    exploit_available: exploit,
    affected_packages: packages.size,
  };
}

/**
 * EPSS — **확률 하나만** 쓴다. `0.0011` 이 아니라 `0.11%` 다.
 *
 * 백분위는 넣지 않는다. "확률 0.11% 인데 상위 12%" 라는 두 숫자가 나란히 있으면
 * 어느 쪽을 봐야 하는지 알 수 없다. 우리가 쓰는 것은 "30일 안에 악용이 관측될
 * 확률" 이고, 그 하나로 충분하다.
 */
export function formatEpss(intel) {
  if (intel?.epss === null || intel?.epss === undefined) return '미확인';
  return formatProbability(intel.epss);
}

export function formatKev(intel) {
  if (intel?.kev === 'true') {
    let text = 'YES';
    if (intel.kev_date_added) text += ` (등재 ${intel.kev_date_added})`;
    if ((intel.kev_ransomware_use || '').toLowerCase() === 'known') text += ' · 랜섬웨어 사용 확인';
    return text;
  }
  if (intel?.kev === 'false') return 'NO';
  return '미확인';
}

export function formatExploit(intel) {
  if (intel?.exploit_available === 'true') {
    const refs = (intel.exploit_sources || [])
      .map((s) => `${EXPLOIT_SOURCE_LABEL[s.source] || s.source} ${s.ref}`)
      .join(', ');
    const maturity = MATURITY_LABEL[intel.exploit_maturity] || '';
    return refs ? `YES (${maturity} · ${refs})` : `YES (${maturity})`;
  }
  if (intel?.exploit_available === 'false') return 'NO (조회한 공개 저장소 기준)';
  return '미확인';
}

export function formatCvss(intel) {
  if (intel?.cvss_score === null || intel?.cvss_score === undefined) return '미확인';
  const sev = SEVERITY_LABEL[intel.severity] || '';
  return `${intel.cvss_score} / ${sev}`;
}
