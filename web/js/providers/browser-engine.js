/**
 * 브라우저 스캔 제공자 — GitHub Pages 데모용.
 *
 * live-api.js 와 **같은 인터페이스**를 구현하므로 프론트엔드의 나머지 코드는
 * 어느 쪽인지 알지 못한다. 다른 것은 스캔이 일어나는 장소뿐이다:
 *
 *   실 운영  → 로컬 FastAPI → 진짜 grype 서브프로세스
 *   데모     → 이 파일     → 진짜 Grype DB에서 만든 정적 인덱스 + 브라우저 매칭
 *
 * 인덱스는 CI에서 진짜 Syft/Grype로 생성되고, 파리티 테스트가 이 엔진의
 * 결과를 Python 파이프라인의 결과와 대조한다. 데모는 시늉이 아니다.
 *
 * 업로드한 SBOM은 어디로도 전송되지 않는다 — 파싱부터 보고서까지 전부
 * 브라우저 안에서 끝난다.
 */

import { EgressGuard, loadEgressPolicy } from '../core/sanitizer.js';
import { PlaybookLibrary } from '../core/playbooks.js';
import { RuleEngine, loadRuleEngine } from '../core/ruleengine.js';
import { VulnIndex, matchPackages, shardKey } from '../core/matcher.js';
import { buildReport } from '../core/report.js';
import { buildBatch } from '../core/vulnfact.js';
import { buildPrompt } from '../core/prompt.js';
import { ToneGuard } from '../core/tone.js';
import { analyze as geminiAnalyze, apiKey, narrativeTexts, toNarrative } from '../core/gemini.js';
import { parseSbom, sha256Hex } from '../core/sbom.js';
import { renderMarkdown } from '../core/render.js';

const BASE = 'demo-data';

const STEPS = [
  ['upload', 'SBOM 업로드'],
  ['detect', '취약점 탐지'],
  ['enrich', '위협정보 보강'],
  ['prioritize', '대응 우선순위'],
  ['rationale', '대응 검토 근거'],
  ['recommend', '권고사항'],
  ['report', '보고서'],
];

const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, '+00:00');

// 스캔 결과를 sessionStorage 에 남긴다. 데모는 페이지마다 모듈이 새로
// 로드되므로(스캔 → 보고서 이동) 메모리에만 두면 결과가 사라진다.
// 탭을 닫으면 함께 사라지며, 어디로도 전송되지 않는다.
const STORAGE_KEY = 'sbomsight.demo.scans';
const MAX_STORED_SCANS = 3;

function loadStored() {
  try {
    return new Map(Object.entries(JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}')));
  } catch {
    return new Map();
  }
}

function saveStored(scans) {
  // 오래된 것부터 버리며 저장을 시도한다. 용량을 넘기면 조용히 포기하되
  // 현재 페이지의 동작은 그대로 유지된다(메모리 사본이 있으므로).
  const entries = [...scans.entries()].slice(-MAX_STORED_SCANS);
  for (let keep = entries.length; keep > 0; keep -= 1) {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(entries.slice(-keep))));
      return;
    } catch {
      // QuotaExceededError — 더 적게 담아 다시 시도한다.
    }
  }
  try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* 무시 */ }
}

class Engine {
  constructor() {
    this.uploads = new Map();
    this.scans = loadStored();
    this.jobs = new Map();
    this._ready = null;
  }

  remember(scanId, entry) {
    this.scans.set(scanId, entry);
    saveStored(this.scans);
  }

  async ready() {
    if (!this._ready) {
      this._ready = (async () => {
        const [index, engine, playbooks, policy] = await Promise.all([
          VulnIndex.load(`${BASE}/vuln-index`),
          loadRuleEngine('rules/priority.json'),
          PlaybookLibrary.load('rules/playbooks'),
          loadEgressPolicy('policy/egress-policy.json'),
        ]);
        return { index, engine, playbooks, guard: new EgressGuard(policy) };
      })();
    }
    return this._ready;
  }

  newScanId() {
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    return `${stamp}-${Math.random().toString(16).slice(2, 10)}`;
  }
}

const engine = new Engine();

function freshSteps() {
  return STEPS.map(([key, label]) => ({
    key, label, state: 'pending', detail: '', metric: '', started_at: '', finished_at: '',
  }));
}

function setStep(job, key, patch) {
  const step = job.steps.find((s) => s.key === key);
  Object.assign(step, patch);
  if (patch.state === 'running') step.started_at = nowIso();
  if (patch.state === 'done') step.finished_at = nowIso();
}

async function runScan(job, upload, { enrich = true } = {}) {
  const { index, engine: rules, playbooks } = await engine.ready();

  // --- 1. 업로드 / 파싱 ------------------------------------------------------
  setStep(job, 'upload', { state: 'running', detail: `${upload.filename} 파싱 중` });
  const [format, packages] = parseSbom(upload.document);
  if (!packages.length) {
    setStep(job, 'upload', { state: 'failed',
      detail: 'SBOM에서 패키지를 찾지 못했습니다. CycloneDX · SPDX · Syft JSON을 올려 주세요.' });
    job.state = 'failed';
    job.error = 'SBOM에서 패키지를 찾지 못했습니다.';
    return;
  }
  setStep(job, 'upload', { state: 'done', metric: `컴포넌트 ${packages.length}개`, detail: format });
  await tick();

  // --- 2. 취약점 탐지 --------------------------------------------------------
  setStep(job, 'detect', { state: 'running', detail: '브라우저 매칭 엔진 실행 중' });
  const { findings, unindexed } = await matchPackages(packages, index);
  const manifest = index.manifest;
  setStep(job, 'detect', {
    state: 'done',
    metric: `${findings.length}건 탐지`,
    detail: `grype ${manifest.grype_version || '?'} DB ${manifest.grype_db_built || '?'} 에서 생성한 인덱스`
      + (unindexed.length ? ` · 인덱스 미수록 ${unindexed.length}개` : ''),
  });
  await tick();

  // --- 3. 위협정보 보강 ------------------------------------------------------
  // 인덱스에 이미 EPSS·KEV·Exploit이 결합되어 있다. 스냅샷 기준일을 표시한다.
  const snapshot = manifest.intel_snapshot || {};
  if (enrich) {
    setStep(job, 'enrich', { state: 'running', detail: '인덱스에 포함된 스냅샷 확인 중' });
    const dates = [...new Set(Object.values(snapshot).filter(Boolean))].sort();
    setStep(job, 'enrich', {
      state: 'done',
      metric: `${Object.keys(snapshot).length}개 소스`,
      detail: dates.length ? `스냅샷 ${dates.join(', ')}` : '스냅샷 정보 없음',
    });
  } else {
    setStep(job, 'enrich', { state: 'skipped',
      detail: '보강을 건너뛰어 EPSS·KEV·Exploit이 미확인으로 남습니다' });
    for (const f of findings) {
      f.intel = { ...f.intel, epss: null, epss_percentile: null, epss_snapshot_date: '',
        kev: 'unknown', exploit_available: 'unknown', exploit_maturity: 'unknown', exploit_sources: [] };
    }
  }
  await tick();

  // --- 4. 대응 우선순위 ------------------------------------------------------
  setStep(job, 'prioritize', { state: 'running', detail: '정책 룰 적용 중' });
  const judged = rules.apply(findings);
  const counts = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const f of judged) counts[f.verdict.priority] += 1;
  setStep(job, 'prioritize', {
    state: 'done',
    metric: Object.entries(counts).filter(([, v]) => v).map(([k, v]) => `${k} ${v}`).join(' · ') || '해당 없음',
    detail: `${rules.sources.join(' + ')} v${rules.version} (sha256:${String(rules.sha256).slice(0, 12)})`,
  });
  await tick();

  // --- 5~7. 근거 · 권고 · 보고서 -----------------------------------------------
  const scanId = engine.newScanId();
  const scan = {
    scan_id: scanId,
    created_at: nowIso(),
    sbom_filename: upload.filename,
    sbom_format: format,
    sbom_sha256: upload.sha256,
    component_count: packages.length,
    grype_version: manifest.grype_version || '',
    grype_db_built: manifest.grype_db_built || '',
    provider: 'browser-engine',
    source: '',
    enrichment: enrich ? (manifest.enrichment || {}) : {},
  };

  setStep(job, 'rationale', { state: 'running', detail: '판정 근거 정리 중' });
  const report = buildReport(scan, judged, { engine: rules, playbooks });
  const withRules = report.findings.filter((i) => i.response_rationale.fired_rules.length).length;
  setStep(job, 'rationale', { state: 'done', metric: `${withRules}건에 발화 룰`,
    detail: '나머지는 기본 등급으로 분류되었습니다' });

  setStep(job, 'recommend', { state: 'running', detail: '패치 절차 생성 중' });
  const fixable = report.findings.filter((i) => i.recommendation.has_fix).length;
  setStep(job, 'recommend', { state: 'done', metric: `패치 가능 ${fixable}건`,
    detail: `수정 버전 없음 ${report.findings.length - fixable}건은 완화 방안 제시` });

  setStep(job, 'report', { state: 'running', detail: '보고서 조립 중' });
  setStep(job, 'report', { state: 'done', metric: `${report.findings.length}개 항목`,
    detail: 'AI 미사용 (룰 기반)' });

  engine.remember(scanId, { scan, findings: judged, report, unindexed });
  job.scan_id = scanId;
  job.state = 'done';
  job.summary = { ...report.summary, component_count: packages.length, unindexed: unindexed.length };
}

/** 각 단계가 화면에 보이도록 이벤트 루프에 양보한다. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 120));

export const browserEngineProvider = {
  name: 'demo',
  label: '브라우저 엔진 (Grype DB 파생 인덱스)',
  capabilities: { upload: true, enrich: true, persist: false, editor: true },

  async health() {
    const { index, engine: rules } = await engine.ready();
    const manifest = index.manifest;
    return {
      ok: true,
      demo: true,
      tools: { syft: manifest.syft_version || '', grype: manifest.grype_version || '',
        grype_db: { built: manifest.grype_db_built || '' } },
      offline: false,
      ai: { enabled: false, ready: false },
      policy: {
        version: rules.version, sha256: rules.sha256, sources: rules.sources,
        label: `${rules.sources.join(' + ')} v${rules.version} (sha256:${String(rules.sha256).slice(0, 12)})`,
      },
      index: {
        generated_at: manifest.generated_at, package_count: manifest.package_count,
        vuln_count: manifest.vuln_count, sources: manifest.sources || [],
        intel_snapshot: manifest.intel_snapshot || {},
      },
    };
  },

  async policy() {
    const response = await fetch('rules/priority.json');
    const policy = await response.json();
    const { engine: rules } = await engine.ready();
    return {
      version: rules.version, sha256: rules.sha256, sources: rules.sources,
      label: `${rules.sources.join(' + ')} v${rules.version} (sha256:${String(rules.sha256).slice(0, 12)})`,
      policy,
    };
  },

  /** 파일은 어디로도 전송되지 않는다 — 브라우저 안에서만 읽는다. */
  async upload(file) {
    const text = await file.text();
    let document;
    try {
      document = JSON.parse(text);
    } catch (error) {
      throw new Error(`JSON으로 읽을 수 없는 파일입니다: ${error.message}`);
    }
    const [format, packages] = parseSbom(document);
    const uploadId = Math.random().toString(16).slice(2, 14);
    engine.uploads.set(uploadId, {
      filename: file.name || 'sbom.json', document, sha256: await sha256Hex(text),
    });
    return {
      upload_id: uploadId, filename: file.name || 'sbom.json', format,
      component_count: packages.length, sha256: await sha256Hex(text), size: text.length,
    };
  },

  async startScan({ uploadId, enrich = true }) {
    const upload = engine.uploads.get(uploadId);
    if (!upload) throw new Error('업로드를 찾을 수 없습니다. 다시 업로드해 주세요.');

    const jobId = Math.random().toString(16).slice(2, 14);
    const job = { job_id: jobId, scan_id: '', state: 'running', error: '',
      created_at: nowIso(), steps: freshSteps(), summary: {} };
    engine.jobs.set(jobId, job);

    // 비동기로 돌려 UI가 진행 상황을 폴링할 수 있게 한다.
    runScan(job, upload, { enrich }).catch((error) => {
      job.state = 'failed';
      job.error = error.message;
      const running = job.steps.find((s) => s.state === 'running');
      if (running) Object.assign(running, { state: 'failed', detail: error.message });
    });

    return { job_id: jobId, steps: job.steps };
  },

  async pollScan(jobId) {
    const job = engine.jobs.get(jobId);
    if (!job) throw new Error('작업을 찾을 수 없습니다.');
    return JSON.parse(JSON.stringify(job));
  },

  async getScan(scanId) {
    const entry = engine.scans.get(scanId);
    if (!entry) throw new Error('스캔을 찾을 수 없습니다.');
    return {
      scan_id: scanId, created_at: entry.scan.created_at, metadata: entry.scan,
      enrichment: entry.scan.enrichment || {}, policy: entry.report.policy,
      findings: entry.findings, unindexed_packages: entry.unindexed,
    };
  },

  async listScans() {
    return {
      scans: [...engine.scans.entries()].reverse().map(([scanId, entry]) => ({
        scan_id: scanId, created_at: entry.scan.created_at,
        finding_count: entry.findings.length, metadata: entry.scan,
        policy: entry.report.policy,
      })),
    };
  },

  async getReport(scanId, format = 'json') {
    const entry = engine.scans.get(scanId);
    if (!entry) throw new Error('스캔을 찾을 수 없습니다.');
    if (format === 'markdown') return renderMarkdown(entry.report);
    if (format === 'html') throw new Error('데모에서는 인쇄(PDF)를 사용해 주세요.');
    return entry.report;
  },

  /**
   * AI에게 전송될 내용 전체. 서버와 같은 조립기·같은 가드를 쓰며,
   * 이 호출 역시 외부로 아무것도 보내지 않는다.
   */
  async egressPreview(scanId, { limit = 0 } = {}) {
    const entry = engine.scans.get(scanId);
    if (!entry) throw new Error('스캔을 찾을 수 없습니다.');
    const { guard } = await engine.ready();

    let facts = buildBatch(entry.findings);
    if (limit) facts = facts.slice(0, limit);
    const checked = guard.check(facts);

    return {
      scan_id: scanId,
      finding_count: entry.findings.length,
      fact_count: facts.length,
      deduplicated: entry.findings.length - facts.length,
      ok: checked.ok,
      violations: checked.violations,
      policy: {
        version: guard.policy.version,
        sha256: await (await import('../core/sanitizer.js')).policyHash(guard.policy),
        label: `egress-policy.json v${guard.policy.version}`,
      },
      facts,
      prompt: buildPrompt(facts),
      would_send: false,
      note: '이 내용이 AI에게 전달되는 전부입니다. 자산명·호스트명·IP·파일 경로·'
        + '설치 버전·취약 여부 판정·대응 우선순위는 포함되지 않습니다.',
    };
  },

  /**
   * 방문자의 API 키로 AI 서술을 생성한다 (선택 기능).
   *
   * 우리 키는 배포물에 없다. 방문자의 키는 sessionStorage 에만 남고 우리 쪽
   * 어디로도 전송되지 않는다. 전송 대상은 egressPreview 가 보여 주는 것과
   * 정확히 같으며, 같은 가드를 통과해야만 호출이 일어난다.
   *
   * 실패하거나 표현 정책에 걸리면 해당 서술을 버리고 룰 문장을 그대로 쓴다 —
   * AI 없이도 보고서가 완결된다는 전제는 데모에서도 지켜진다.
   */
  async generateNarratives(scanId, { key = apiKey.get(), model, onProgress = null } = {}) {
    const entry = engine.scans.get(scanId);
    if (!entry) throw new Error('스캔을 찾을 수 없습니다.');
    if (!key) throw new Error('API 키가 필요합니다.');

    const { guard, engine: rules, playbooks } = await engine.ready();
    const tone = await ToneGuard.load('rules/tone-policy.json');

    const facts = buildBatch(entry.findings);
    const limit = guard.limits.max_facts_per_request || facts.length;
    const narratives = {};
    const rejected = [];

    for (let start = 0; start < facts.length; start += limit) {
      const chunk = facts.slice(start, start + limit);
      if (onProgress) onProgress({ done: start, total: facts.length });

      // guard 를 넘기면 전송 직전에 다시 검증한다. 통과 못 하면 호출하지 않는다.
      const result = await geminiAnalyze(chunk, { key, guard, ...(model ? { model } : {}) });

      for (const analysis of result.analyses) {
        const cve = String(analysis.cve || '');
        if (!cve) continue;
        const narrative = toNarrative(analysis);
        const violations = tone.inspect(narrativeTexts(narrative));
        if (violations.length) {
          rejected.push({ cve, rules: violations.map((v) => v.rule) });
          continue;   // 표현 정책 위반 — 룰 문장을 그대로 쓴다
        }
        narratives[cve] = narrative;
      }
    }
    if (onProgress) onProgress({ done: facts.length, total: facts.length });

    // 보고서를 AI 서술과 함께 다시 조립한다. 우선순위는 룰 판정 그대로다.
    entry.report = buildReport(entry.scan, entry.findings, {
      engine: rules, playbooks, narratives,
    });
    engine.remember(scanId, entry);

    return { applied: Object.keys(narratives).length, total: facts.length, rejected };
  },

  /** 샘플 SBOM 목록. 방문자가 내려받아 수정한 뒤 다시 올릴 수 있다. */
  async sampleSboms() {
    const { index } = await engine.ready();
    return (index.manifest.sources || []).map((s) => ({
      name: s.name, path: `${BASE}/${s.sbom}`, components: s.components,
    }));
  },
};
