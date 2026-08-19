/**
 * 대응 검토 우선순위 판정 — core/ruleengine.py 의 동형 구현.
 *
 * 결정론적이며, 어떤 룰이 왜 발화했는지가 함께 나온다. AI는 이 판정에
 * 관여하지 않는다. 산출물은 로컬 전용이라 이그레스 경계를 넘지 않는다.
 *
 * rules/priority.json 을 Python 구현과 **같은 파일**로 읽는다.
 */

const MISSING = Symbol('missing');

const isMissing = (v) => v === null || v === undefined || v === MISSING || v === '';

/** Finding에서 룰이 참조하는 평면 객체를 만든다. */
export function buildContext(finding) {
  const intel = finding.intel || {};
  const fix = finding.fix || {};
  return {
    // 공개 신호 — 우선순위 levels 는 이것만 참조한다
    cvss_score: intel.cvss_score ?? null,
    severity: intel.severity || 'unknown',
    epss: intel.epss ?? null,
    epss_percentile: intel.epss_percentile ?? null,
    kev: intel.kev || 'unknown',
    exploit_available: intel.exploit_available || 'unknown',
    exploit_maturity: intel.exploit_maturity || 'unknown',
    // 로컬 사실 — flags 전용
    fix_state: fix.fix_state || 'unknown',
    is_vulnerable: fix.is_vulnerable || 'unknown',
    update_available: fix.update_available || 'unknown',
    // 신선도
    epss_snapshot_date: intel.epss_snapshot_date || '',
    kev_snapshot_date: intel.kev_snapshot_date || '',
  };
}

/** 신호 하나를 평가해 [발화 여부, 근거 문자열]을 돌려준다. */
function evaluate(spec, context) {
  const field = spec.field || '';
  const op = spec.op || '';
  const threshold = spec.value;
  const value = field in context ? context[field] : MISSING;
  const label = spec.label || field;

  if (op === 'is_missing') return [isMissing(value), isMissing(value) ? `${label} (값 없음)` : ''];
  if (op === 'is_unknown') return [value === 'unknown', value === 'unknown' ? label : ''];
  if (op === 'is_true') {
    const hit = value === 'true' || value === true;
    return [hit, hit ? label : ''];
  }
  if (op === 'is_false') {
    const hit = value === 'false' || value === false;
    return [hit, hit ? label : ''];
  }

  // 값이 없으면 비교 연산은 발화하지 않는다. "데이터가 없음"과 "낮음"은
  // 다른 이야기이며, 전자는 flags(unknown_*)로 따로 표기된다.
  if (isMissing(value) || value === 'unknown') return [false, ''];

  if (op === 'in') {
    const options = Array.isArray(threshold) ? threshold : [threshold];
    const hit = options.includes(value);
    return [hit, hit ? `${label} (${value})` : ''];
  }
  if (op === '==') return [value === threshold, value === threshold ? `${label} (${value})` : ''];
  if (op === '!=') return [value !== threshold, value !== threshold ? `${label} (${value})` : ''];

  const numeric = Number(value);
  const limit = Number(threshold);
  if (Number.isNaN(numeric) || Number.isNaN(limit)) return [false, ''];

  const symbol = { '>=': '≥', '>': '>', '<=': '≤', '<': '<' }[op];
  if (!symbol) return [false, ''];
  const hit = { '>=': numeric >= limit, '>': numeric > limit,
    '<=': numeric <= limit, '<': numeric < limit }[op];
  // Python의 f"{x:g}" 와 같은 표기 (불필요한 0 제거)
  const fmt = (n) => String(Number(n));
  return [hit, hit ? `${label} (${fmt(numeric)} ${symbol} ${fmt(limit)})` : ''];
}

export class RuleEngine {
  constructor(policy, { version = '', sha256 = '', sources = [] } = {}) {
    this.policy = policy;
    this.signals = policy.signals || {};
    this.levels = policy.levels || [];
    this.flagSpecs = policy.flags || {};
    this.version = version || policy.version || '0';
    this.sha256 = sha256;
    this.sources = sources;
  }

  evaluate(finding, { staleDays = 7 } = {}) {
    const context = buildContext(finding);

    const fired = {};
    for (const [name, spec] of Object.entries(this.signals)) {
      const [hit, explain] = evaluate(spec, context);
      if (hit) fired[name] = explain;
    }

    let priority = 'P3';
    let matched = [];
    outer:
    for (const level of this.levels) {
      for (const group of level.when || [[]]) {
        if (group.every((signal) => signal in fired)) {
          priority = level.priority || 'P3';
          matched = group.map((signal) => ({ name: signal, explain: fired[signal] }));
          break outer;
        }
      }
    }

    const flags = [];
    for (const [name, spec] of Object.entries(this.flagSpecs)) {
      if (evaluate(spec, context)[0]) flags.push(name);
    }
    if (this._isStale(finding, staleDays)) flags.push('stale_snapshot');

    return {
      priority,
      fired_rules: matched,
      flags,
      policy_version: this.version,
      policy_sha256: this.sha256,
    };
  }

  _isStale(finding, staleDays) {
    const today = new Date();
    for (const value of [finding.intel?.epss_snapshot_date, finding.intel?.kev_snapshot_date]) {
      if (!value) continue;
      const snapshot = new Date(`${String(value).slice(0, 10)}T00:00:00Z`);
      if (Number.isNaN(snapshot.getTime())) continue;
      if ((today - snapshot) / 86400000 > staleDays) return true;
    }
    return false;
  }

  apply(findings, options) {
    return findings.map((f) => ({ ...f, verdict: this.evaluate(f, options) }));
  }

  describeLevel(priority) {
    return this.levels.find((l) => l.priority === priority) || { priority, label: priority };
  }
}

export async function loadRuleEngine(url = 'rules/priority.json', overrideUrl = null) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`우선순위 정책을 읽지 못했습니다 (${response.status})`);
  let policy = await response.json();
  const sources = [url.split('/').pop()];

  if (overrideUrl) {
    try {
      const extra = await fetch(overrideUrl);
      if (extra.ok) {
        policy = { ...policy, ...(await extra.json()) };
        sources.push(overrideUrl.split('/').pop());
      }
    } catch { /* 오버라이드가 없는 것은 정상이다 */ }
  }

  const { policyHash } = await import('./sanitizer.js');
  const sha256 = await policyHash(policy);
  return new RuleEngine(policy, { version: policy.version, sha256, sources });
}
