/**
 * 이그레스 가드 (브라우저 구현).
 *
 * core/sanitizer.py 와 **같은 정책 파일**(policy/egress-policy.json)을 읽고
 * 같은 판정을 내야 한다. 두 구현의 동치성은 policy/egress-test-vectors.json
 * 으로 검증한다 (tests/js/sanitizer.test.mjs, tests/test_egress.py).
 *
 * 브라우저에도 가드를 두는 이유: GitHub Pages 데모에서 방문자가 자기 키로
 * Gemini를 직접 호출할 때, 서버를 거치지 않으므로 이 구현이 유일한 방어다.
 */

let cachedPolicy = null;

export async function loadEgressPolicy(url = '/policy/egress-policy.json') {
  if (cachedPolicy) return cachedPolicy;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`이그레스 정책을 읽지 못했습니다 (${response.status})`);
  cachedPolicy = await response.json();
  return cachedPolicy;
}

/** JSON 정책의 sha256. Python 쪽 canonical_hash 와 같은 방식(키 정렬·공백 제거). */
export async function policyHash(policy) {
  const stripped = stripComments(policy);
  const canonical = stableStringify(stripped);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function stripComments(node) {
  if (Array.isArray(node)) return node.map(stripComments);
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      if (!k.startsWith('_')) out[k] = stripComments(v);
    }
    return out;
  }
  return node;
}

/** 키를 정렬하고 공백 없이 직렬화한다 (Python json.dumps(sort_keys=True, separators=(',',':'))와 동일). */
function stableStringify(node) {
  if (node === null) return 'null';
  if (Array.isArray(node)) return `[${node.map(stableStringify).join(',')}]`;
  if (typeof node === 'object') {
    const keys = Object.keys(node).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(node[k])}`).join(',')}}`;
  }
  return JSON.stringify(node);
}

export class EgressGuard {
  constructor(policy) {
    this.policy = policy;
    this.allowed = policy.allowed_fields || {};
    this.forbiddenNames = new Set((policy.forbidden_field_names || []).map((n) => n.toLowerCase()));
    this.limits = policy.limits || {};
    // 플래그는 정책에 명시된 것만 쓴다. (?i) 같은 인라인 플래그는 JS가
    // 컴파일하지 못하므로 정책에서 금지되어 있다.
    this.patterns = (policy.forbidden_patterns || []).map((spec) => ({
      name: spec.name,
      re: new RegExp(spec.pattern, spec.flags || ''),
      reason: spec.reason || '',
    }));
    this._fieldRe = new Map();
  }

  static async load(url) {
    return new EgressGuard(await loadEgressPolicy(url));
  }

  _re(pattern) {
    if (!this._fieldRe.has(pattern)) this._fieldRe.set(pattern, new RegExp(pattern));
    return this._fieldRe.get(pattern);
  }

  // --- 1·2단계: 스키마와 값 -------------------------------------------------

  _checkScalar(spec, value, path) {
    const out = [];
    const expected = spec.type || 'string';

    if (value === null || value === undefined) {
      if (!spec.nullable) out.push({ rule: 'type', path, reason: '값이 없는데 nullable이 아님', sample: '' });
      return out;
    }

    if (expected === 'number') {
      if (typeof value !== 'number' || Number.isNaN(value)) {
        out.push({ rule: 'type', path, reason: `number가 아님 (${typeof value})`, sample: '' });
        return out;
      }
      if (spec.min !== undefined && value < spec.min)
        out.push({ rule: 'range', path, reason: `${value} < 최솟값 ${spec.min}`, sample: '' });
      if (spec.max !== undefined && value > spec.max)
        out.push({ rule: 'range', path, reason: `${value} > 최댓값 ${spec.max}`, sample: '' });
      return out;
    }

    if (typeof value !== 'string') {
      out.push({ rule: 'type', path, reason: `string이 아님 (${typeof value})`, sample: '' });
      return out;
    }

    if (spec.max_length !== undefined && value.length > spec.max_length)
      out.push({ rule: 'range', path, reason: `길이 ${value.length} > ${spec.max_length}`, sample: '' });
    if (spec.enum && !spec.enum.includes(value))
      out.push({ rule: 'pattern', path, reason: `허용 값이 아님: ${value.slice(0, 40)}`, sample: value.slice(0, 40) });
    if (spec.pattern) {
      const m = this._re(spec.pattern).exec(value);
      // Python의 re.match 는 문자열 시작에서만 맞춘다. JS도 같게 맞춘다.
      if (!m || m.index !== 0) {
        out.push({ rule: 'pattern', path, reason: `형식 불일치: ${spec.pattern}`, sample: value.slice(0, 60) });
      }
    }
    return out;
  }

  _checkObject(spec, value, path) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return [{ rule: 'type', path, reason: `object가 아님 (${typeof value})`, sample: '' }];
    }
    const fields = spec.fields || {};
    const out = [];
    for (const key of Object.keys(value)) {
      if (this.forbiddenNames.has(key.toLowerCase()))
        out.push({ rule: 'forbidden_field', path: `${path}.${key}`, reason: '금칙 필드명', sample: '' });
      else if (!(key in fields))
        out.push({ rule: 'unknown_field', path: `${path}.${key}`, reason: '허용 목록에 없는 키', sample: '' });
    }
    for (const [key, fieldSpec] of Object.entries(fields)) {
      if (key in value) out.push(...this._checkScalar(fieldSpec, value[key], `${path}.${key}`));
    }
    return out;
  }

  _checkField(spec, value, path) {
    if ((spec.type || 'string') === 'array') {
      if (!Array.isArray(value))
        return [{ rule: 'type', path, reason: `array가 아님 (${typeof value})`, sample: '' }];
      const out = [];
      if (spec.max_items !== undefined && value.length > spec.max_items)
        out.push({ rule: 'range', path, reason: `항목 ${value.length} > ${spec.max_items}`, sample: '' });
      const itemSpec = spec.items || {};
      value.forEach((item, index) => {
        const itemPath = `${path}[${index}]`;
        out.push(...(itemSpec.type === 'object'
          ? this._checkObject(itemSpec, item, itemPath)
          : this._checkScalar(itemSpec, item, itemPath)));
      });
      return out;
    }
    return this._checkScalar(spec, value, path);
  }

  _checkSchema(fact, path) {
    const out = [];
    if (fact === null || typeof fact !== 'object' || Array.isArray(fact)) {
      return [{ rule: 'type', path, reason: 'VulnFact가 object가 아님', sample: '' }];
    }
    for (const key of Object.keys(fact)) {
      if (this.forbiddenNames.has(key.toLowerCase()))
        out.push({ rule: 'forbidden_field', path: `${path}.${key}`, reason: '금칙 필드명 — 내부 정보일 수 있음', sample: '' });
      else if (!(key in this.allowed))
        out.push({ rule: 'unknown_field', path: `${path}.${key}`, reason: '허용 목록에 없는 키', sample: '' });
    }
    for (const [key, spec] of Object.entries(this.allowed)) {
      if (!(key in fact)) {
        if (spec.required) out.push({ rule: 'type', path: `${path}.${key}`, reason: '필수 필드 누락', sample: '' });
        continue;
      }
      out.push(...this._checkField(spec, fact[key], `${path}.${key}`));
    }
    return out;
  }

  // --- 3단계: 금칙 패턴 -----------------------------------------------------

  *_walkStrings(node, path) {
    if (typeof node === 'string') yield [path, node];
    else if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) yield* this._walkStrings(node[i], `${path}[${i}]`);
    } else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) yield* this._walkStrings(v, `${path}.${k}`);
    }
  }

  _checkPatterns(fact, path) {
    const out = [];
    for (const [valuePath, text] of this._walkStrings(fact, path)) {
      for (const { name, re, reason } of this.patterns) {
        const m = re.exec(text);
        if (m) {
          out.push({
            rule: 'forbidden_pattern', path: valuePath,
            reason: `${name}: ${reason}`, sample: m[0].slice(0, 60),
          });
        }
      }
    }
    return out;
  }

  // --- 공개 진입점 ----------------------------------------------------------

  check(facts) {
    const violations = [];
    const maxFacts = this.limits.max_facts_per_request;
    if (maxFacts && facts.length > maxFacts) {
      violations.push({ rule: 'range', path: 'facts',
        reason: `한 요청 최대 ${maxFacts}건인데 ${facts.length}건`, sample: '' });
    }

    facts.forEach((fact, index) => {
      const path = `facts[${index}]`;
      violations.push(...this._checkSchema(fact, path));
      violations.push(...this._checkPatterns(fact, path));
    });

    const maxBytes = this.limits.max_payload_bytes;
    if (maxBytes) {
      const size = new TextEncoder().encode(JSON.stringify(facts)).length;
      if (size > maxBytes)
        violations.push({ rule: 'range', path: 'facts', reason: `크기 ${size}B > 한도 ${maxBytes}B`, sample: '' });
    }

    return { ok: violations.length === 0, facts, violations };
  }

  /** 검증에 실패하면 던진다. 일부만 골라 보내지 않는다 — 전부 아니면 아무것도. */
  enforce(facts) {
    const result = this.check(facts);
    if (!result.ok) {
      const head = result.violations.slice(0, 5)
        .map((v) => `${v.rule}@${v.path}: ${v.reason}`).join('; ');
      const error = new Error(`외부 전송이 차단되었습니다 (${head})`);
      error.violations = result.violations;
      throw error;
    }
    return result.facts;
  }
}
