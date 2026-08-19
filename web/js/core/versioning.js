/**
 * 생태계별 버전 비교자 — core/versioning.py 의 동형 구현.
 *
 * 두 구현은 tests/fixtures/version-vectors.json 의 **같은 벡터**로 채점받는다
 * (tests/test_versioning.py, tests/js/parity.test.mjs). rpm 케이스는 rpm
 * 프로젝트의 rpmvercmp 테스트 스위트에서 온 것이며, 이 비교가 어긋나면
 * FixAnalysis가 틀리고 그것은 곧 패치 누락이 된다.
 *
 * 비교할 수 없으면 **null을 돌려준다.** 호출부는 이를 'unknown'으로 옮긴다.
 */

// ---------------------------------------------------------------------------
// rpm — rpmvercmp.c 포팅
// ---------------------------------------------------------------------------

const isAsciiAlnum = (c) => /[0-9A-Za-z]/.test(c);
const isDigit = (c) => c >= '0' && c <= '9';
const isAlpha = (c) => /[A-Za-z]/.test(c);

function rpmvercmp(one, two) {
  if (one === two) return 0;

  let i = 0;
  let j = 0;
  const len1 = one.length;
  const len2 = two.length;

  while (i < len1 || j < len2) {
    // 영숫자도 ~ 도 ^ 도 아닌 구분자는 건너뛴다.
    while (i < len1 && !(isAsciiAlnum(one[i]) || one[i] === '~' || one[i] === '^')) i += 1;
    while (j < len2 && !(isAsciiAlnum(two[j]) || two[j] === '~' || two[j] === '^')) j += 1;

    const c1 = i < len1 ? one[i] : '';
    const c2 = j < len2 ? two[j] : '';

    // `~`는 무엇보다도 앞선다 — 문자열의 끝보다도 앞선다.
    if (c1 === '~' || c2 === '~') {
      if (c1 !== '~') return 1;
      if (c2 !== '~') return -1;
      i += 1; j += 1;
      continue;
    }

    // `^`는 개념은 ~와 같으나, 한쪽이 끝났으면(base version) 다른 쪽이 높다.
    if (c1 === '^' || c2 === '^') {
      if (!c1) return -1;
      if (!c2) return 1;
      if (c1 !== '^') return 1;
      if (c2 !== '^') return -1;
      i += 1; j += 1;
      continue;
    }

    if (!(c1 && c2)) break;

    const start1 = i;
    const start2 = j;
    let isNum;
    if (isDigit(one[i])) {
      while (i < len1 && isDigit(one[i])) i += 1;
      while (j < len2 && isDigit(two[j])) j += 1;
      isNum = true;
    } else {
      while (i < len1 && isAlpha(one[i])) i += 1;
      while (j < len2 && isAlpha(two[j])) j += 1;
      isNum = false;
    }

    let seg1 = one.slice(start1, i);
    let seg2 = two.slice(start2, j);

    // 한쪽만 세그먼트가 비었다 = 타입이 다르다. 숫자가 알파보다 항상 높다.
    if (!seg2) return isNum ? 1 : -1;

    if (isNum) {
      seg1 = seg1.replace(/^0+/, '');
      seg2 = seg2.replace(/^0+/, '');
      if (seg1.length > seg2.length) return 1;
      if (seg2.length > seg1.length) return -1;
    }

    if (seg1 !== seg2) return seg1 < seg2 ? -1 : 1;
  }

  const rest1 = i < len1;
  const rest2 = j < len2;
  if (!rest1 && !rest2) return 0;
  return !rest1 ? -1 : 1;
}

const EVR_RE = /^(?:(\d+):)?([^-]*)(?:-(.*))?$/;

function splitEvr(value) {
  const m = EVR_RE.exec(value.trim());
  if (!m) return null;
  const version = m[2] || '';
  if (!version) return null;
  return [m[1] || '0', version, m[3] || ''];
}

export function rpmCompare(a, b) {
  const left = splitEvr(a);
  const right = splitEvr(b);
  if (!left || !right) return null;

  let rc = rpmvercmp(left[0], right[0]);
  if (rc) return rc;
  rc = rpmvercmp(left[1], right[1]);
  if (rc) return rc;
  // release가 한쪽에만 있으면 비교하지 않는다. advisory가 "5.6.2"라고만
  // 말했는데 설치본이 "5.6.2-1.el9"인 경우 release로 갈라서면 안 된다.
  if (!left[2] || !right[2]) return 0;
  return rpmvercmp(left[2], right[2]);
}

// ---------------------------------------------------------------------------
// deb — dpkg verrevcmp 포팅
// ---------------------------------------------------------------------------

function debOrder(c) {
  if (!c) return 0;
  if (isDigit(c)) return 0;
  if (isAlpha(c)) return c.charCodeAt(0);
  if (c === '~') return -1;
  return c.charCodeAt(0) + 256;
}

function verrevcmp(a, b) {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = debOrder(i < a.length ? a[i] : '');
      const bc = debOrder(j < b.length ? b[j] : '');
      if (ac !== bc) return ac < bc ? -1 : 1;
      i += 1; j += 1;
    }
    while (i < a.length && a[i] === '0') i += 1;
    while (j < b.length && b[j] === '0') j += 1;
    while (i < a.length && isDigit(a[i]) && j < b.length && isDigit(b[j])) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i += 1; j += 1;
    }
    if (i < a.length && isDigit(a[i])) return 1;
    if (j < b.length && isDigit(b[j])) return -1;
    if (firstDiff) return firstDiff < 0 ? -1 : 1;
  }
  return 0;
}

const DEB_RE = /^(?:(\d+):)?([^:]*?)(?:-([^-]*))?$/;

export function debCompare(a, b) {
  const ma = DEB_RE.exec(a.trim());
  const mb = DEB_RE.exec(b.trim());
  if (!ma || !mb) return null;

  const ea = Number(ma[1] || 0);
  const eb = Number(mb[1] || 0);
  if (ea !== eb) return ea < eb ? -1 : 1;

  const rc = verrevcmp(ma[2] || '', mb[2] || '');
  if (rc) return rc;

  if (!ma[3] || !mb[3]) return 0;
  return verrevcmp(ma[3], mb[3]);
}

// ---------------------------------------------------------------------------
// semver
// ---------------------------------------------------------------------------

const SEMVER_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;

function semverParse(value) {
  const m = SEMVER_RE.exec(value.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0), m[4] ? m[4].split('.') : []];
}

function cmpPrerelease(a, b) {
  // prerelease가 없는 쪽이 더 높다 (1.0.0 > 1.0.0-rc1).
  if (!a.length && !b.length) return 0;
  if (!a.length) return 1;
  if (!b.length) return -1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i];
    const y = b[i];
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (xn !== yn) {
      return xn ? -1 : 1;   // 숫자 식별자가 문자 식별자보다 낮다
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

export function semverCompare(a, b) {
  const pa = semverParse(a);
  const pb = semverParse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i += 1) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return cmpPrerelease(pa[3], pb[3]);
}

// ---------------------------------------------------------------------------
// PEP 440
// ---------------------------------------------------------------------------

const PEP440_RE = new RegExp(
  '^\\s*v?(?:(\\d+)!)?(\\d+(?:\\.\\d+)*)'
  + '(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\\d+)?)?'
  + '(?:(?:-(\\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\\d+)?))?'
  + '(?:[-_.]?(dev)[-_.]?(\\d+)?)?'
  + '(?:\\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\\s*$',
  'i',
);

const PRE_NORM = { alpha: 'a', beta: 'b', c: 'rc', pre: 'rc', preview: 'rc' };

function pep440Key(value) {
  const m = PEP440_RE.exec(value);
  if (!m) return null;

  const epoch = Number(m[1] || 0);
  const release = m[2].split('.').map(Number);
  while (release.length > 1 && release[release.length - 1] === 0) release.pop();

  let pre = null;
  if (m[3]) {
    let letter = m[3].toLowerCase();
    letter = PRE_NORM[letter] || letter;
    pre = [letter, Number(m[4] || 0)];
  }

  let post = null;
  if (m[5] !== undefined) post = Number(m[5]);
  else if (m[6]) post = Number(m[7] || 0);

  const dev = m[8] ? Number(m[9] || 0) : null;

  // dev < pre < release < post 순서가 나오도록 키를 만든다.
  let preKey;
  if (pre === null && post === null && dev !== null) preKey = [-1, '', 0];
  else if (pre === null) preKey = [1, '', 0];
  else preKey = [0, pre[0], pre[1]];

  const postKey = post === null ? [0, 0] : [1, post];
  const devKey = dev === null ? [1, 0] : [0, dev];

  return [epoch, release, preKey, postKey, devKey];
}

/** Python 튜플 비교와 같은 규칙: 원소별로 비교하고, 길이가 다르면 짧은 쪽이 작다. */
function tupleCompare(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
      const rc = tupleCompare(a[i], b[i]);
      if (rc) return rc;
    }
    if (a.length === b.length) return 0;
    return a.length < b.length ? -1 : 1;
  }
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

export function pep440Compare(a, b) {
  const ka = pep440Key(a);
  const kb = pep440Key(b);
  if (!ka || !kb) return null;
  return tupleCompare(ka, kb);
}

// ---------------------------------------------------------------------------
// generic — 최후의 수단
// ---------------------------------------------------------------------------

export function genericCompare(a, b) {
  const ta = a.trim().match(/\d+|[A-Za-z]+/g) || [];
  const tb = b.trim().match(/\d+|[A-Za-z]+/g) || [];
  if (!ta.length || !tb.length) return null;
  const n = Math.min(ta.length, tb.length);
  for (let i = 0; i < n; i += 1) {
    const x = ta[i];
    const y = tb[i];
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (xn !== yn) {
      return xn ? 1 : -1;   // 숫자를 더 높게 본다 (rpm 관례)
    } else if (x.toLowerCase() !== y.toLowerCase()) {
      return x.toLowerCase() < y.toLowerCase() ? -1 : 1;
    }
  }
  if (ta.length === tb.length) return 0;
  return ta.length < tb.length ? -1 : 1;
}

// ---------------------------------------------------------------------------
// 디스패치
// ---------------------------------------------------------------------------

const COMPARATORS = {
  rpm: rpmCompare,
  deb: debCompare,
  semver: semverCompare,
  pep440: pep440Compare,
  generic: genericCompare,
};

const ECOSYSTEM_COMPARATOR = {
  rpm: 'rpm', rhel: 'rpm', redhat: 'rpm', centos: 'rpm', rocky: 'rpm',
  almalinux: 'rpm', amazonlinux: 'rpm', sles: 'rpm', opensuse: 'rpm',
  deb: 'deb', dpkg: 'deb', debian: 'deb', ubuntu: 'deb',
  npm: 'semver', javascript: 'semver', node: 'semver',
  'go-module': 'semver', golang: 'semver', go: 'semver',
  cargo: 'semver', 'rust-crate': 'semver', gem: 'semver', ruby: 'semver',
  composer: 'semver', 'php-composer': 'semver',
  python: 'pep440', pypi: 'pep440', 'python-pkg': 'pep440',
  wheel: 'pep440', egg: 'pep440',
};

export function comparatorFor(ecosystem) {
  if (!ecosystem) return 'generic';
  return ECOSYSTEM_COMPARATOR[String(ecosystem).trim().toLowerCase()] || 'generic';
}

export function compare(a, b, comparator = 'generic') {
  if (a === null || a === undefined || b === null || b === undefined) return null;
  const left = String(a).trim();
  const right = String(b).trim();
  if (!left || !right) return null;
  const fn = COMPARATORS[comparator] || genericCompare;
  try {
    return fn(left, right);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 제약식 평가
// ---------------------------------------------------------------------------

// `<<` 와 `>>` 는 dpkg의 엄격 비교 연산자다. 긴 것을 먼저 매칭해야 한다.
const OP_RE = /^\s*(<<|>>|>=|<=|==|!=|=|>|<)?\s*(.+?)\s*$/;
const OPERAND_RE = /^[A-Za-z0-9][A-Za-z0-9.:~^+_*-]*$/;

const OPS = {
  '<': (rc) => rc < 0,
  '<<': (rc) => rc < 0,
  '<=': (rc) => rc <= 0,
  '>': (rc) => rc > 0,
  '>>': (rc) => rc > 0,
  '>=': (rc) => rc >= 0,
  '=': (rc) => rc === 0,
  '==': (rc) => rc === 0,
  '!=': (rc) => rc !== 0,
};

function evalClause(version, clause, comparator) {
  const m = OP_RE.exec(clause);
  if (!m) return null;
  const op = m[1] || '=';
  const operand = m[2];
  if (!OPERAND_RE.test(operand)) return null;
  const rc = compare(version, operand, comparator);
  if (rc === null) return null;
  return OPS[op](rc);
}

/**
 * version이 constraint를 만족하는지. 판단할 수 없으면 null.
 *
 * 지원 문법 (Grype가 내보내는 형태):
 *   "< 5.6.2"  /  ">=5.6.0,<5.6.2"(AND)  /  "<1.2.3 || >=2.0.0,<2.1.0"(OR)
 */
export function satisfies(version, constraint, comparator = 'generic') {
  if (!constraint || !String(constraint).trim()) return null;
  if (!version || !String(version).trim()) return null;

  // Grype는 "제약 없음"을 "none"으로 표현한다. 해당 패키지의 모든 버전이
  // 영향 범위라는 뜻이지, 버전 이름이 아니다.
  const normalized = String(constraint).trim().toLowerCase();
  if (normalized === '*' || normalized === 'none' || normalized === 'all') return true;

  let sawUnknown = false;
  for (const orGroup of String(constraint).split('||')) {
    const clauses = orGroup.split(',').filter((c) => c.trim());
    if (!clauses.length) continue;
    let group = true;
    let groupUnknown = false;
    for (const clause of clauses) {
      const rc = evalClause(version, clause, comparator);
      if (rc === null) { groupUnknown = true; break; }
      if (!rc) { group = false; break; }
    }
    if (groupUnknown) { sawUnknown = true; continue; }
    if (group) return true;
  }
  return sawUnknown ? null : false;
}

/** 설치 버전과 수정 버전 사이의 거리를 major/minor/patch로 요약한다. */
export function versionGap(installed, fixed, comparator = 'generic') {
  const rc = compare(installed, fixed, comparator);
  if (rc === null) return 'unknown';   // 비교조차 못 하는데 격차를 말할 수 없다
  if (rc === 0) return 'none';

  const ta = (String(installed || '').match(/\d+|[A-Za-z]+/g) || [])
    .filter((t) => /^\d+$/.test(t)).map(Number);
  const tb = (String(fixed || '').match(/\d+|[A-Za-z]+/g) || [])
    .filter((t) => /^\d+$/.test(t)).map(Number);
  if (!ta.length || !tb.length) return 'unknown';

  const labels = ['major', 'minor', 'patch'];
  for (let i = 0; i < 3; i += 1) {
    if ((ta[i] || 0) !== (tb[i] || 0)) return labels[i];
  }
  return 'patch';
}
