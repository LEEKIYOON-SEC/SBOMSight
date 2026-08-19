/**
 * 파리티 테스트 — JavaScript 구현이 Python 구현과 같은 결과를 내는가.
 *
 * 이 테스트가 GitHub Pages 데모를 '시늉'이 아니게 만든다. 브라우저에서
 * 돌아가는 것이 서버에서 돌아가는 것과 같은 판정을 내지 않으면, 데모는
 * 실제 동작을 보여 주는 것이 아니라 흉내에 불과하다.
 *
 * 대조 항목:
 *   1. 버전 비교자      — tests/fixtures/version-vectors.json (152건)
 *   2. FixAnalysis      — 같은 입력에 같은 판정
 *   3. Rule Engine      — 우선순위·발화 룰·플래그
 *   4. 프롬프트          — 바이트 단위 일치
 *   5. 보고서 서술       — 룰 기반 문장이 같은가
 *
 * Python 쪽 기대값은 tests/fixtures/parity-expected.json 에 있으며
 * scripts/gen_parity_fixture.py 가 실제 Python 구현을 돌려 생성한다.
 *
 * 실행: node tests/js/parity.test.mjs
 */

import { readFileSync } from 'node:fs';

import { compare, comparatorFor, satisfies, versionGap } from '../../web/js/core/versioning.js';
import { analyzeFix } from '../../web/js/core/fixanalysis.js';
import { RuleEngine } from '../../web/js/core/ruleengine.js';
import { PlaybookLibrary } from '../../web/js/core/playbooks.js';
import { buildReport } from '../../web/js/core/report.js';
import { buildPrompt } from '../../web/js/core/prompt.js';
import { buildBatch } from '../../web/js/core/vulnfact.js';

const read = (p) => JSON.parse(readFileSync(p, 'utf8'));
const versionVectors = read('tests/fixtures/version-vectors.json');
const expected = read('tests/fixtures/parity-expected.json');

let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) { passed += 1; return; }
  failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

function checkEqual(name, actual, want) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(want);
  check(name, a === b, `\n      js: ${a}\n      py: ${b}`);
}

// --- 1. 버전 비교자 ----------------------------------------------------------
{
  const fns = { rpm: 'rpm', deb: 'deb', semver: 'semver', pep440: 'pep440' };
  for (const [name] of Object.entries(fns)) {
    for (const [a, b, want] of versionVectors.compare[name]) {
      check(`compare/${name}(${a}, ${b})`, compare(a, b, name) === want,
        `js=${compare(a, b, name)} py=${want}`);
    }
  }
  for (const [c, a, b] of versionVectors.uncomparable) {
    check(`uncomparable/${c}(${a}, ${b})`, compare(a, b, c) === null);
  }
  for (const [c, v, expr, want] of versionVectors.satisfies) {
    check(`satisfies/${c}(${v}, ${expr})`, satisfies(v, expr, c) === want,
      `js=${satisfies(v, expr, c)} py=${want}`);
  }
  for (const [c, a, b, want] of versionVectors.version_gap) {
    check(`versionGap/${c}(${a}, ${b})`, versionGap(a, b, c) === want);
  }
  for (const [eco, want] of versionVectors.comparator_for) {
    check(`comparatorFor(${eco})`, comparatorFor(eco) === want);
  }
}

// --- 2. FixAnalysis ----------------------------------------------------------
for (const item of expected.fix_analysis) {
  checkEqual(`FixAnalysis: ${item.name}`,
    analyzeFix(item.installed, item.advisory, { detectedByScanner: item.detected_by_scanner }),
    item.expected);
}

// --- 3. Rule Engine ----------------------------------------------------------
{
  const engine = new RuleEngine(expected.priority_policy, {
    version: expected.policy_version,
    sha256: expected.policy_sha256,
    sources: expected.policy_sources,
  });
  for (const item of expected.rule_engine) {
    const verdict = engine.evaluate(item.finding, { staleDays: item.stale_days ?? 7 });
    checkEqual(`RuleEngine: ${item.name}`, verdict, item.expected);
  }
}

// --- 4. 프롬프트 -------------------------------------------------------------
{
  const facts = buildBatch(expected.findings);
  checkEqual('VulnFact 조립', facts, expected.vuln_facts);
  check('프롬프트 바이트 일치', buildPrompt(facts) === expected.prompt,
    `js 길이 ${buildPrompt(facts).length}, py 길이 ${expected.prompt.length}`);
}

// --- 5. 보고서 (룰 기반 서술) --------------------------------------------------
{
  const engine = new RuleEngine(expected.priority_policy, {
    version: expected.policy_version,
    sha256: expected.policy_sha256,
    sources: expected.policy_sources,
  });
  const playbooks = new PlaybookLibrary(expected.playbooks);
  const report = buildReport(expected.scan, expected.findings, { engine, playbooks });

  check('보고서 항목 수', report.findings.length === expected.report.findings.length,
    `js=${report.findings.length} py=${expected.report.findings.length}`);
  checkEqual('보고서 요약', report.summary, expected.report.summary);

  for (let i = 0; i < Math.min(report.findings.length, expected.report.findings.length); i += 1) {
    const js = report.findings[i];
    const py = expected.report.findings[i];
    check(`보고서[${i}] CVE 순서`, js.cve === py.cve, `js=${js.cve} py=${py.cve}`);
    checkEqual(`보고서[${i}] ${py.cve} ②기술적 위험성`, js.technical_risk, py.technical_risk);
    checkEqual(`보고서[${i}] ${py.cve} ③악용 가능성 서술`,
      js.exploitability.narrative, py.exploitability.narrative);
    checkEqual(`보고서[${i}] ${py.cve} ④대응 필요성`, js.response_rationale, py.response_rationale);
    checkEqual(`보고서[${i}] ${py.cve} ⑤권고사항`, js.recommendation, py.recommendation);
    checkEqual(`보고서[${i}] ${py.cve} 근거 배지`, js.badge, py.badge);
    checkEqual(`보고서[${i}] ${py.cve} Reference`, js.references, py.references);
    checkEqual(`보고서[${i}] ${py.cve} [로컬 분석 정보]`, js.local_analysis, py.local_analysis);
    checkEqual(`보고서[${i}] ${py.cve} 플래그`, js.flags, py.flags);
  }
}

console.log(`통과 ${passed}건`);
if (failures.length) {
  console.error(`\n실패 ${failures.length}건:`);
  for (const f of failures.slice(0, 20)) console.error('  ✗', f);
  if (failures.length > 20) console.error(`  ... 외 ${failures.length - 20}건`);
  process.exit(1);
}
console.log('파리티 — Python 구현과 모든 결과가 일치');
