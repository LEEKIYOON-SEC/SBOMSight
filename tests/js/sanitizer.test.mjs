/**
 * 이그레스 가드 JS 구현 적합성 테스트.
 *
 * policy/egress-test-vectors.json — Python 테스트(tests/test_egress.py)가 읽는
 * 것과 **같은 파일**을 읽는다. 두 구현이 같은 판정을 내지 않으면 여기서 깨진다.
 *
 * 실행: node tests/js/sanitizer.test.mjs
 */

import { readFileSync } from 'node:fs';
import { EgressGuard, policyHash } from '../../web/js/core/sanitizer.js';
import { buildVulnFact, buildBatch } from '../../web/js/core/vulnfact.js';

const policy = JSON.parse(readFileSync('policy/egress-policy.json', 'utf8'));
const vectors = JSON.parse(readFileSync('policy/egress-test-vectors.json', 'utf8'));
const guard = new EgressGuard(policy);

let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) { passed += 1; return; }
  failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

function makeFact(vector) {
  const fact = { ...vectors.base_fact, ...(vector.patch || {}) };
  for (const key of vector.remove || []) delete fact[key];
  return fact;
}

// --- 공용 벡터 --------------------------------------------------------------
for (const vector of vectors.vectors) {
  const result = guard.check([makeFact(vector)]);
  if (vector.expect === 'pass') {
    check(vector.name, result.ok, JSON.stringify(result.violations));
  } else {
    check(vector.name, !result.ok, '차단되어야 하는데 통과함');
    if (vector.rule && !result.ok) {
      const rules = new Set(result.violations.map((v) => v.rule));
      check(`${vector.name} (규칙)`, rules.has(vector.rule),
        `기대 ${vector.rule}, 실제 ${[...rules].join(',')}`);
    }
  }
}

for (const vector of vectors.batch_vectors) {
  const facts = Array.from({ length: vector.repeat_base }, () => ({ ...vectors.base_fact }));
  const result = guard.check(facts);
  check(vector.name, result.ok === (vector.expect === 'pass'));
  if (vector.expect === 'block' && vector.rule) {
    check(`${vector.name} (규칙)`, result.violations.some((v) => v.rule === vector.rule));
  }
}

// --- 조립기 -----------------------------------------------------------------
{
  const fact = buildVulnFact(
    { advisory_package: 'xz', advisory_ecosystem: 'rpm',
      affected_version_range: '< 5.6.2', fixed_version: '5.6.2', os_family: 'rhel' },
    { cve: 'CVE-2024-3094', severity: 'critical', cvss_score: 10.0,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      kev: 'true', exploit_available: 'true', exploit_maturity: 'weaponized',
      exploit_sources: [
        { source: 'exploit_db', ref: 'EDB-52128', note: '3층 WEB 서버에서 확인' },
        { source: 'internal_redteam', ref: 'OP-2026-01' },
      ] },
  );
  check('조립: 허용 키만 남는다', Object.keys(fact).every((k) => k in policy.allowed_fields));
  check('조립: 정책의 모든 필드를 만든다',
    Object.keys(policy.allowed_fields).every((k) => k in fact));
  check('조립: 자유 텍스트 note가 제거된다', !JSON.stringify(fact).includes('3층'));
  check('조립: 허용 목록 밖 exploit 출처가 제거된다',
    fact.exploit_sources.length === 1 && fact.exploit_sources[0].source === 'exploit_db');
  check('조립: 결과가 가드를 통과한다', guard.check([fact]).ok,
    JSON.stringify(guard.check([fact]).violations));
}

{
  const finding = (version) => ({
    installed: { name: 'xz', version, type: 'rpm', locations: ['/var/lib/rpm'] },
    advisory: { advisory_package: 'xz', advisory_ecosystem: 'rpm', fixed_version: '5.6.2' },
    intel: { cve: 'CVE-2024-3094' },
    fix: { is_vulnerable: 'true' },
    verdict: { priority: 'P0' },
  });
  const facts = buildBatch([finding('5.6.0-1.el9'), finding('5.6.0-2.el9')]);
  check('조립: 같은 CVE·패키지는 한 번만', facts.length === 1);
  const payload = JSON.stringify(facts);
  check('조립: 설치 버전이 남지 않는다', !payload.includes('5.6.0-2.el9'));
  check('조립: 파일 경로가 남지 않는다', !payload.includes('/var/lib/rpm'));
  check('조립: 우선순위 판정이 남지 않는다', !payload.includes('P0'));
}

// --- enforce 는 전부 아니면 아무것도 ------------------------------------------
{
  const clean = { ...vectors.base_fact };
  const dirty = { ...vectors.base_fact, priority: 'P0' };
  let threw = false;
  try { guard.enforce([clean, dirty]); } catch { threw = true; }
  check('enforce: 하나라도 위반이면 전부 차단', threw);
}

// --- 정책 해시가 Python과 같은가 ----------------------------------------------
{
  const hash = await policyHash(policy);
  const expected = process.argv[2];   // Python이 계산한 값을 인자로 받는다
  if (expected) {
    check('정책 해시가 Python 구현과 일치', hash === expected, `js=${hash} py=${expected}`);
  }
}

console.log(`통과 ${passed}건`);
if (failures.length) {
  console.error(`\n실패 ${failures.length}건:`);
  for (const f of failures) console.error('  ✗', f);
  process.exit(1);
}
console.log('JS 이그레스 가드 — 모든 벡터 통과');
