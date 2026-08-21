/**
 * 브라우저 AI 경로 가드 테스트.
 *
 * 데모에서는 서버가 없으므로 **브라우저 가드가 유일한 방어**다. 여기서
 * 지키는 계약:
 *
 *   1. 키가 없으면 네트워크 호출이 일어나지 않는다.
 *   2. 이그레스 가드를 통과하지 못하면 네트워크 호출이 일어나지 않는다.
 *   3. 전송 payload에 내부 정보가 없다.
 *   4. AI 응답이 대응 검토 우선순위를 바꾸지 못한다.
 *   5. 표현 정책 위반 서술은 걸러진다 — Python 구현과 같은 판정으로.
 *
 * 실행: node tests/js/ai-guard.test.mjs
 */

import { readFileSync } from 'node:fs';

import { EgressGuard } from '../../web/js/core/sanitizer.js';
import { ToneGuard } from '../../web/js/core/tone.js';
import { analyze, narrativeTexts, toNarrative } from '../../web/js/core/gemini.js';
import { RESPONSE_SCHEMA } from '../../web/js/core/prompt.js';
import { buildBatch } from '../../web/js/core/vulnfact.js';

const read = (p) => JSON.parse(readFileSync(p, 'utf8'));
const egressPolicy = read('policy/egress-policy.json');
const tonePolicy = read('rules/tone-policy.json');
const vectors = read('policy/egress-test-vectors.json');
const expected = read('tests/fixtures/parity-expected.json');

const guard = new EgressGuard(egressPolicy);
const tone = new ToneGuard(tonePolicy);

let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) { passed += 1; return; }
  failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

// fetch 를 가로채 호출 여부와 payload 를 기록한다.
const calls = [];
globalThis.fetch = async (url, options = {}) => {
  calls.push({ url: String(url), options });
  return {
    ok: true,
    status: 200,
    async json() {
      return {
        candidates: [{ content: { parts: [{ text: JSON.stringify({ analyses: [] }) }] } }],
      };
    },
    async text() { return ''; },
  };
};

// --- 1. 키가 없으면 호출하지 않는다 --------------------------------------------
{
  calls.length = 0;
  let threw = false;
  try {
    await analyze([{ ...vectors.base_fact }], { key: '' });
  } catch (error) {
    threw = /API 키/.test(error.message);
  }
  check('키 없으면 예외', threw);
  check('키 없으면 네트워크 호출 없음', calls.length === 0, `호출 ${calls.length}건`);
}

// --- 2. 가드를 통과하지 못하면 호출하지 않는다 ---------------------------------
{
  const hostile = [
    ['설치 버전이 섞임', { installed_version: '5.6.0-2.el9' }],
    ['우선순위 판정이 섞임', { priority: 'P0' }],
    ['파일 경로가 섞임', { locations: ['/var/lib/rpm'] }],
    ['값 안에 IP', { advisory_package: 'svc-10.20.30.40' }],
    ['값 안에 한글', { advisory_package: '인사시스템' }],
  ];
  for (const [name, patch] of hostile) {
    calls.length = 0;
    let blocked = false;
    try {
      await analyze([{ ...vectors.base_fact, ...patch }], { key: 'test-key', guard });
    } catch (error) {
      blocked = Array.isArray(error.violations) && error.violations.length > 0;
    }
    check(`가드 차단: ${name}`, blocked);
    check(`가드 차단 시 호출 없음: ${name}`, calls.length === 0, `호출 ${calls.length}건`);
  }
}

// --- 3. 정상 payload 는 호출되고, 내부 정보가 없다 ------------------------------
{
  calls.length = 0;
  const facts = buildBatch(expected.findings);
  await analyze(facts, { key: 'test-key', guard });

  check('정상 payload 는 호출된다', calls.length === 1, `호출 ${calls.length}건`);
  check('키가 헤더로 간다', calls[0]?.options?.headers?.['x-goog-api-key'] === 'test-key');
  check('엔드포인트가 Google', /generativelanguage\.googleapis\.com/.test(calls[0]?.url || ''));

  const sent = calls[0].options.body;
  // 시스템 지시문에는 "P0~P3 등급을 말하지 마십시오" 같은 가드 문구가 들어 있다.
  // 유출 검사는 실제 데이터가 실리는 요청 본문만 대상으로 한다.
  const requestBody = sent.includes('=== 요청 ===') ? sent.split('=== 요청 ===')[1] : sent;
  const internal = ['5.6.0-2.el9', '1:3.0.7-24.el9', '7.0.3', '/var/lib/rpm',
    'rocky:distro:rocky:9', 'rpm-matcher', 'kev_listed', 'exact-direct-match'];
  const leaked = internal.filter((s) => requestBody.includes(s));
  check('전송 payload 에 내부 정보 없음', leaked.length === 0, leaked.join(', '));
}

// --- 4. AI 응답이 우선순위를 바꾸지 못한다 --------------------------------------
{
  check('응답 스키마에 priority 자리 없음',
    !JSON.stringify(RESPONSE_SCHEMA).includes('priority'));

  const narrative = toNarrative({
    cve: 'CVE-2024-3094',
    technical_risk: '서술',
    priority: 'P0',
    risk_level: 'critical',
    verdict: { priority: 'P0' },
    is_vulnerable: true,
    update_available: false,
  });
  check('Narrative 에 priority 없음', !('priority' in narrative));
  check('Narrative 에 verdict 없음', !('verdict' in narrative));
  check('Narrative 에 is_vulnerable 없음', !('is_vulnerable' in narrative));
  check('서술은 보존된다', narrative.technical_risk === '서술');
  check('출처가 ai 로 표시된다', narrative.source === 'ai');
}

// --- 5. 표현 정책 — Python 구현과 같은 판정 -------------------------------------
{
  const forbidden = [
    ['귀사의 WEB 서버는 매우 위험합니다.', 'first_person_org'],
    ['우리 조직에 Critical 위험입니다.', 'first_person_org'],
    ['해당 서버는 반드시 패치해야 합니다.', 'asset_reference'],
    ['사내 운영 서버에 적용하십시오.', 'asset_reference'],
    ['반드시 패치를 적용해야 합니다.', 'imperative_must'],
    ['이 취약점은 매우 위험합니다.', 'risk_assertion'],
    ['이 항목은 P0 등급에 해당합니다.', 'priority_claim'],
    ['우선순위는 P1 입니다.', 'priority_claim'],
    ['방치하면 반드시 악용될 것입니다.', 'breach_prediction'],
    ['조치 방법:\ndnf upgrade openssl', 'fabricated_command'],
  ];
  for (const [text, rule] of forbidden) {
    const rules = tone.inspect({ response_rationale: text }).map((v) => v.rule);
    check(`표현 차단: ${rule}`, rules.includes(rule), `실제 ${rules.join(',') || '(없음)'}`);
  }

  const allowed = [
    '공개된 위협정보를 기준으로 볼 때 우선적인 대응을 검토할 필요가 있습니다.',
    'CISA KEV 등재 및 공개 Exploit 존재를 고려할 때 신속한 대응이 권고됩니다.',
    'CVSS 벡터상 네트워크를 통해 인증 없이 접근 가능한 형태로 분류됩니다.',
    '높은 우선순위로 조치하는 것을 권고합니다.',
    '공개된 정보만으로는 확인되지 않습니다.',
  ];
  for (const text of allowed) {
    const rules = tone.inspect({ technical_risk: text }).map((v) => v.rule);
    check(`표현 허용: ${text.slice(0, 24)}…`, rules.length === 0, rules.join(','));
  }

  check('narrativeTexts 는 서술 4종을 낸다',
    Object.keys(narrativeTexts(toNarrative({}))).length === 4);
}

console.log(`통과 ${passed}건`);
if (failures.length) {
  console.error(`\n실패 ${failures.length}건:`);
  for (const f of failures) console.error('  ✗', f);
  process.exit(1);
}
console.log('브라우저 AI 경로 — 모든 가드 통과');
