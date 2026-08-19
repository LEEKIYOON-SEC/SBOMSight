/**
 * 브라우저 취약점 매칭 엔진.
 *
 * 정적 인덱스는 CI에서 **진짜 Syft + 진짜 Grype**로 만들어진다
 * (scripts/build_demo_index.py). 여기서 하는 일은 Grype가 하는 것과 같다 —
 * 설치 버전이 advisory의 영향 버전범위에 드는지 생태계 규칙으로 판정한다.
 *
 * 파리티 테스트(tests/js/parity.test.mjs)가 이 매처의 결과를 Python 파이프라인의
 * 결과와 대조한다. 데모가 시늉이 아니라는 것을 그 테스트가 증명한다.
 *
 * **인덱스에 없는 패키지를 조용히 "취약점 없음"으로 처리하지 않는다.**
 * 인덱스가 아는 패키지(covered)와 취약점이 있는 패키지(vulns)를 구분해
 * "인덱스 미수록"을 정직하게 표기한다.
 */

import { analyzeFix } from './fixanalysis.js';
import { comparatorFor, satisfies } from './versioning.js';

/** 패키지명을 샤드 버킷으로. Python 빌더와 같은 규칙이어야 한다. */
export function shardKey(ecosystem, name) {
  const eco = String(ecosystem || 'unknown').toLowerCase();
  const first = String(name || '').trim().toLowerCase()[0] || '_';
  const bucket = /[a-z0-9]/.test(first) ? first : '_';
  return `${eco}-${bucket}`;
}

export class VulnIndex {
  constructor(manifest, { base = 'demo-data/vuln-index' } = {}) {
    this.manifest = manifest;
    this.base = base;
    this._shards = new Map();     // 샤드 키 → {covered:Set, vulns:{}}
    this._loading = new Map();
  }

  static async load(base = 'demo-data/vuln-index') {
    const response = await fetch(`${base}/index.json`);
    if (!response.ok) throw new Error(`취약점 인덱스를 읽지 못했습니다 (${response.status})`);
    return new VulnIndex(await response.json(), { base });
  }

  get availableShards() {
    return new Set(this.manifest.shards || []);
  }

  /** 필요한 샤드만 받아온다. 없는 샤드는 요청하지 않는다. */
  async loadShards(keys) {
    const available = this.availableShards;
    const wanted = [...new Set(keys)].filter((k) => available.has(k) && !this._shards.has(k));

    await Promise.all(wanted.map(async (key) => {
      if (this._loading.has(key)) return this._loading.get(key);
      const promise = (async () => {
        const response = await fetch(`${this.base}/${key}.json`);
        if (!response.ok) {
          this._shards.set(key, { covered: new Set(), vulns: {} });
          return;
        }
        const data = await response.json();
        this._shards.set(key, {
          covered: new Set(data.covered || []),
          vulns: data.vulns || {},
        });
      })();
      this._loading.set(key, promise);
      return promise;
    }));
  }

  covers(ecosystem, name) {
    const shard = this._shards.get(shardKey(ecosystem, name));
    return Boolean(shard && shard.covered.has(name));
  }

  vulnsFor(ecosystem, name) {
    const shard = this._shards.get(shardKey(ecosystem, name));
    return (shard && shard.vulns[name]) || [];
  }
}

/**
 * 설치 패키지 목록을 인덱스에 대고 매칭한다.
 *
 * 반환은 서버 파이프라인과 **같은 Finding 형태**다. 프론트엔드의 나머지
 * 코드는 이것이 브라우저에서 만들어졌는지 알지 못한다.
 */
export async function matchPackages(packages, index, { onProgress = null } = {}) {
  await index.loadShards(packages.map((p) => shardKey(p.type, p.name)));

  const findings = [];
  const unindexed = [];
  const seen = new Set();

  for (const pkg of packages) {
    if (!index.covers(pkg.type, pkg.name)) {
      unindexed.push(`${pkg.name}@${pkg.version || '?'}`);
      continue;
    }

    const comparator = comparatorFor(pkg.type);
    for (const entry of index.vulnsFor(pkg.type, pkg.name)) {
      const constraint = entry.constraint || '';
      const hit = satisfies(pkg.version, constraint, comparator);
      // null(판단 불가)도 후보로 남긴다 — 조용히 버리면 그 취약점이 사라진다.
      if (hit === false) continue;

      const advisory = {
        advisory_package: entry.advisory_package || pkg.name,
        advisory_ecosystem: entry.advisory_ecosystem || pkg.type,
        affected_version_range: constraint,
        fixed_version: entry.fixed_version || '',
        fix_state: entry.fix_state || 'unknown',
        os_family: entry.os_family || '',
      };
      const intel = {
        cve: entry.cve,
        aliases: entry.aliases || [],
        severity: entry.severity || 'unknown',
        cvss_score: entry.cvss_score ?? null,
        cvss_vector: entry.cvss_vector || '',
        cvss_version: entry.cvss_version || '',
        cwe: entry.cwe || [],
        description: entry.description || '',
        published: entry.published || '',
        references: entry.references || [],
        epss: entry.epss ?? null,
        epss_percentile: entry.epss_percentile ?? null,
        epss_snapshot_date: entry.epss_snapshot_date || '',
        kev: entry.kev || 'unknown',
        kev_date_added: entry.kev_date_added || '',
        kev_ransomware_use: entry.kev_ransomware_use || '',
        kev_snapshot_date: entry.kev_snapshot_date || '',
        exploit_available: entry.exploit_available || 'unknown',
        exploit_maturity: entry.exploit_maturity || 'unknown',
        exploit_sources: entry.exploit_sources || [],
      };

      const key = `${intel.cve}|${pkg.name}|${pkg.version}|${pkg.purl}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        installed: pkg,
        advisory,
        intel,
        detection: {
          matcher: entry.matcher || 'browser-matcher',
          match_type: 'exact-direct-match',
          namespace: entry.namespace || '',
          search_criteria: { package: { name: pkg.name, version: pkg.version } },
        },
        fix: analyzeFix(pkg, advisory, { detectedByScanner: hit === true }),
        verdict: null,
      });
    }

    if (onProgress) onProgress(findings.length);
  }

  return { findings, unindexed };
}
