/**
 * CVSS 벡터와 CWE를 사람이 읽는 사실로 옮긴다 — core/cvss.py 의 동형.
 *
 * 해석이 아니라 번역이다. "AV:N/AC:L/PR:N/UI:N"이 무슨 뜻인지 풀어 쓸 뿐
 * 새로운 판단을 더하지 않는다. 덕분에 AI 없이도 ②기술적 위험성이 채워진다.
 */

const VECTOR_RE = /([A-Z]+):([A-Z]+)/g;

const AV = { N: '네트워크', A: '인접 네트워크', L: '로컬', P: '물리적 접근' };
const AC = { L: '낮음', H: '높음' };
const PR = { N: '불필요', L: '일반 사용자 권한 필요', H: '관리자 권한 필요' };
const UI = { N: '불필요', R: '사용자 조작 필요', P: '수동적 사용자 조작 필요', A: '능동적 사용자 조작 필요' };
const SCOPE = { U: '변경 없음', C: '변경됨 (다른 구성요소로 영향 확산)' };
const IMPACT = { H: '높음', L: '낮음', N: '없음' };

const CWE_LABELS = {
  'CWE-22': '경로 탐색 (Path Traversal)',
  'CWE-77': '명령어 삽입 (Command Injection)',
  'CWE-78': 'OS 명령어 삽입 (OS Command Injection)',
  'CWE-79': '크로스사이트 스크립팅 (XSS)',
  'CWE-89': 'SQL 삽입 (SQL Injection)',
  'CWE-94': '코드 삽입 (Code Injection)',
  'CWE-119': '메모리 버퍼 경계 위반',
  'CWE-120': '버퍼 오버플로',
  'CWE-125': '범위 밖 읽기 (Out-of-bounds Read)',
  'CWE-190': '정수 오버플로',
  'CWE-200': '민감 정보 노출',
  'CWE-269': '부적절한 권한 관리',
  'CWE-287': '부적절한 인증',
  'CWE-295': '부적절한 인증서 검증',
  'CWE-306': '중요 기능에 대한 인증 누락',
  'CWE-352': '크로스사이트 요청 위조 (CSRF)',
  'CWE-362': '경쟁 조건 (Race Condition)',
  'CWE-400': '자원 소모 제어 실패',
  'CWE-401': '메모리 누수',
  'CWE-416': '해제 후 사용 (Use-After-Free)',
  'CWE-434': '위험한 형식의 파일 업로드 제한 없음',
  'CWE-476': 'NULL 포인터 역참조',
  'CWE-502': '신뢰할 수 없는 데이터 역직렬화',
  'CWE-506': '악성 코드 삽입 (Embedded Malicious Code)',
  'CWE-611': 'XML 외부 개체 참조 (XXE)',
  'CWE-770': '제한 없는 자원 할당',
  'CWE-787': '범위 밖 쓰기 (Out-of-bounds Write)',
  'CWE-798': '하드코딩된 자격증명',
  'CWE-863': '부적절한 인가',
  'CWE-918': '서버 측 요청 위조 (SSRF)',
  'CWE-1321': '프로토타입 오염',
};

const MEMORY_SAFETY = new Set(['CWE-119', 'CWE-120', 'CWE-125', 'CWE-416', 'CWE-476', 'CWE-787', 'CWE-190']);
const DOS_ORIENTED = new Set(['CWE-400', 'CWE-401', 'CWE-770', 'CWE-476']);

export function parseVector(vector) {
  if (!vector) return {};
  const metrics = {};
  for (const m of String(vector).toUpperCase().matchAll(VECTOR_RE)) metrics[m[1]] = m[2];
  delete metrics.CVSS;
  return metrics;
}

export function describeCvss(vector) {
  const metrics = parseVector(vector);
  if (!Object.keys(metrics).length) {
    return { parsed: false, preconditions: [], impacts: [], remote_unauthenticated: false };
  }

  const version = ('VC' in metrics || 'AT' in metrics) ? '4.0' : '3.x';
  // v4.0은 영향 메트릭 이름이 다르다 (VC/VI/VA = Vulnerable system).
  const conf = metrics.C || metrics.VC || '';
  const integ = metrics.I || metrics.VI || '';
  const avail = metrics.A || metrics.VA || '';
  const { AV: av = '', AC: ac = '', PR: pr = '', UI: ui = '' } = metrics;

  const preconditions = [];
  if (av) preconditions.push(`공격 경로: ${AV[av] || av}`);
  if (ac) preconditions.push(`공격 난이도: ${AC[ac] || ac}`);
  if ('AT' in metrics) preconditions.push(`추가 공격 조건: ${metrics.AT === 'N' ? '불필요' : '필요'}`);
  if (pr) preconditions.push(`필요 권한: ${PR[pr] || pr}`);
  if (ui) preconditions.push(`사용자 상호작용: ${UI[ui] || ui}`);
  if (metrics.S) preconditions.push(`영향 범위(Scope): ${SCOPE[metrics.S] || metrics.S}`);

  const impacts = [];
  if (conf && conf !== 'N') impacts.push(`기밀성 영향 ${IMPACT[conf] || conf} — 정보 노출 가능성`);
  if (integ && integ !== 'N') impacts.push(`무결성 영향 ${IMPACT[integ] || integ} — 데이터 변조 가능성`);
  if (avail && avail !== 'N') impacts.push(`가용성 영향 ${IMPACT[avail] || avail} — 서비스 중단 가능성`);

  return {
    parsed: true,
    version,
    attack_vector: AV[av] || av,
    attack_complexity: AC[ac] || ac,
    privileges_required: PR[pr] || pr,
    user_interaction: UI[ui] || ui,
    scope: SCOPE[metrics.S] || '',
    confidentiality: IMPACT[conf] || conf,
    integrity: IMPACT[integ] || integ,
    availability: IMPACT[avail] || avail,
    preconditions,
    impacts,
    remote_unauthenticated: av === 'N' && pr === 'N' && ui === 'N',
  };
}

export function cweLabel(cwe) {
  return CWE_LABELS[cwe] ? `${cwe} ${CWE_LABELS[cwe]}` : cwe;
}

/**
 * 공격 성공 시 나타날 수 있는 영향 유형. CVSS 영향 메트릭과 CWE를 조합한
 * **가능성 분류**이지 단정이 아니다.
 */
export function classifyImpact(vector, cwes = []) {
  const facts = describeCvss(vector);
  const cweSet = new Set(cwes.map((c) => String(c).toUpperCase()));
  const has = (set) => [...cweSet].some((c) => set.has(c));
  const labels = [];

  const highAll = facts.confidentiality === '높음' && facts.integrity === '높음' && facts.availability === '높음';
  const memoryIssue = has(MEMORY_SAFETY);
  const injection = ['CWE-77', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-1321'].some((c) => cweSet.has(c));

  if ((highAll && facts.remote_unauthenticated)
    || (memoryIssue && facts.attack_vector === '네트워크') || injection) {
    labels.push('원격 코드 실행 (RCE) 가능성');
  }
  if (['높음', '낮음'].includes(facts.integrity)
    && ['CWE-269', 'CWE-863', 'CWE-287', 'CWE-306', 'CWE-798'].some((c) => cweSet.has(c))) {
    labels.push('권한 상승 · 인가 우회 가능성');
  }
  if (facts.availability === '높음' || has(DOS_ORIENTED)) labels.push('서비스 거부 (DoS) 가능성');
  if (['높음', '낮음'].includes(facts.confidentiality)
    || ['CWE-200', 'CWE-125', 'CWE-22', 'CWE-918', 'CWE-611'].some((c) => cweSet.has(c))) {
    labels.push('정보 노출 가능성');
  }
  if (['높음', '낮음'].includes(facts.integrity) && !labels.some((l) => l.startsWith('원격 코드'))) {
    labels.push('데이터 변조 가능성');
  }

  return [...new Set(labels)];
}
