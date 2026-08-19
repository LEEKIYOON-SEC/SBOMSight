/**
 * 보고서 조립 — core/report.py 의 동형 구현.
 *
 * AI 없이도 ②기술적 위험성, ③악용 가능성, ④대응 필요성 분석이 룰 문장으로
 * 채워진다. 서버와 같은 문장이 나와야 하며, 파리티 테스트가 이를 대조한다.
 */

import { classifyImpact, cweLabel, describeCvss } from './cvss.js';
import { EXPLOIT_SOURCE_LABEL, MATURITY_LABEL, SEVERITY_LABEL, priorityRank } from './model.js';

export const DISCLAIMER = '이 보고서는 공개된 취약점 데이터(CVSS · EPSS · CISA KEV · 공개 Exploit)와 '
  + '로컬 SBOM/Grype 탐지 결과를 결합해 **대응 여부를 검토하기 위한 근거**를 정리한 것이다. '
  + "여기서 제시하는 '대응 검토 우선순위'는 아래 명시된 정책 룰을 공개 데이터에 적용한 결과이며, "
  + '조직 내부의 실제 위험도와 최종적인 패치 여부는 자산의 노출 경로·보상 통제·업무 영향을 함께 '
  + '고려해 보안담당자가 판단한다.';

const FLAG_INFO = {
  no_fix_available: ['수정 버전 없음', '패치로 해소할 수 없으므로 완화 방안 검토가 필요하다'],
  update_available: ['업데이트 가능', '상위 버전으로 갱신할 수 있다'],
  vulnerability_unconfirmed: ['취약 여부 판단 불가', '버전 문자열을 비교할 수 없어 영향 여부를 확정하지 못했다. 수동 확인이 필요하다'],
  unknown_epss: ['EPSS 미확인', 'EPSS 데이터를 확보하지 못했다. 악용 가능성이 낮다는 뜻이 아니다'],
  unknown_exploit: ['Exploit 존재 여부 미확인', '공개 exploit 존재 여부를 확인하지 못했다. 없다는 뜻이 아니다'],
  unknown_kev: ['KEV 조회 실패', 'CISA KEV 카탈로그를 조회하지 못했다'],
  no_cvss: ['CVSS 미확인', 'CVSS 점수를 확보하지 못해 심각도 기반 판정이 적용되지 않았다'],
  stale_snapshot: ['위협정보 스냅샷 오래됨', 'EPSS/KEV 스냅샷이 기준일보다 오래되었다. 최신 데이터로 재판정이 필요하다'],
};

// --- 룰 기반 서술 -----------------------------------------------------------

function ruleTechnicalRisk(finding) {
  const intel = finding.intel || {};
  const facts = describeCvss(intel.cvss_vector);
  const impacts = classifyImpact(intel.cvss_vector, intel.cwe || []);

  if (!facts.parsed) {
    return [
      'CVSS 벡터를 확보하지 못해 공격 조건을 구조적으로 분석할 수 없다. '
      + '아래 Reference의 벤더 advisory에서 직접 확인이 필요하다.',
      [], impacts,
    ];
  }

  const pieces = [];
  if (facts.remote_unauthenticated) {
    pieces.push('CVSS 벡터상 네트워크를 통해 인증이나 사용자 조작 없이 접근 가능한 형태로 분류된다');
  } else {
    const conditions = [];
    if (facts.attack_vector) conditions.push(`공격 경로는 ${facts.attack_vector}`);
    if (facts.privileges_required && facts.privileges_required !== '불필요') conditions.push(facts.privileges_required);
    if (facts.user_interaction && facts.user_interaction !== '불필요') conditions.push(facts.user_interaction);
    pieces.push(`CVSS 벡터상 ${conditions.join(', ')}한 조건에서 악용될 수 있는 형태로 분류된다`);
  }
  if (impacts.length) pieces.push(`공격이 성립할 경우 ${impacts.join(' · ')}이 제시된다`);
  if ((intel.cwe || []).length) {
    pieces.push(`취약점 유형은 ${intel.cwe.map(cweLabel).join(', ')}으로 분류되어 있다`);
  }
  return [`${pieces.join('. ')}.`, facts.preconditions, impacts];
}

function ruleExploitabilityNote(finding) {
  const intel = finding.intel || {};
  const parts = [];

  if (intel.kev === 'true') {
    parts.push(`CISA가 실제 악용을 확인해 KEV 카탈로그에 등재한 취약점이다${
      intel.kev_date_added ? ` (${intel.kev_date_added} 등재)` : ''}`);
    if (String(intel.kev_ransomware_use || '').toLowerCase() === 'known') {
      parts.push('랜섬웨어 캠페인에서의 사용이 확인되었다');
    }
  } else if (intel.kev === 'false') {
    parts.push('CISA KEV 카탈로그에는 등재되어 있지 않다');
  } else {
    parts.push('CISA KEV 등재 여부를 확인하지 못했다');
  }

  if (intel.epss !== null && intel.epss !== undefined) {
    // 숫자 뒤 조사는 읽는 방식에 따라 갈리므로 붙이지 않는다.
    let sentence = `EPSS 점수는 ${intel.epss.toFixed(4)} — 향후 30일 내 악용 시도가 관측될 확률이 `
      + `${(intel.epss * 100).toFixed(1)}%로 추정된다`;
    if (intel.epss_percentile !== null && intel.epss_percentile !== undefined) {
      sentence += ` (전체 CVE 중 상위 ${((1 - intel.epss_percentile) * 100).toFixed(1)}% 구간)`;
    }
    parts.push(sentence);
  } else {
    parts.push('EPSS 점수를 확보하지 못했다 (악용 가능성이 낮다는 뜻은 아니다)');
  }

  if (intel.exploit_available === 'true') {
    const names = [...new Set((intel.exploit_sources || [])
      .map((s) => EXPLOIT_SOURCE_LABEL[s.source] || s.source))].sort();
    parts.push(`공개된 exploit/PoC가 확인된다 (${names.join(', ')}). `
      + `성숙도 분류: ${MATURITY_LABEL[intel.exploit_maturity] || '미확인'}`);
  } else if (intel.exploit_available === 'false') {
    parts.push('조회한 공개 exploit 저장소에서는 exploit/PoC가 확인되지 않았다');
  } else {
    parts.push('공개 exploit 존재 여부를 확인하지 못했다 (없다는 뜻은 아니다)');
  }

  return `${parts.join('. ')}.`;
}

function ruleResponseRationale(finding, engine) {
  const verdict = finding.verdict;
  if (!verdict) return '우선순위 판정이 수행되지 않았다.';

  const level = engine.describeLevel(verdict.priority);
  const label = level.label || verdict.priority;
  const fired = verdict.fired_rules || [];

  const head = fired.length
    ? `${fired.map((r) => r.explain || r.name).join(', ')}가 관측되어 적용 정책상 `
      + `'${verdict.priority} ${label}' 구간으로 분류된다`
    : `우선순위 상향 조건에 해당하는 신호가 관측되지 않아 '${verdict.priority} ${label}' 구간으로 분류된다`;

  const tail = [];
  const flags = verdict.flags || [];
  if (flags.includes('no_fix_available')) {
    tail.push('공개된 수정 버전이 없어 업데이트로는 해소할 수 없으므로 완화 방안 검토가 함께 필요하다');
  }
  if (flags.includes('vulnerability_unconfirmed')) {
    tail.push('설치 버전 문자열을 비교할 수 없어 실제 영향 여부가 확정되지 않았다. 수동 확인이 필요하다');
  }
  if (flags.includes('stale_snapshot')) {
    tail.push('판정에 사용한 위협정보 스냅샷이 오래되어 최신 데이터로 재확인이 권고된다');
  }

  return [`${head}.`, ...tail.map((t) => `${t}.`),
    '해당 구성요소의 노출 경로와 업무 영향을 함께 고려해 대응 시점을 결정하는 것이 권고된다.'].join(' ');
}

// --- 배지 · Reference --------------------------------------------------------

function buildBadge(finding, engine) {
  const intel = finding.intel || {};
  const verdict = finding.verdict;

  let cvss = '미확인';
  if (intel.cvss_score !== null && intel.cvss_score !== undefined) {
    cvss = `${intel.cvss_score} / ${SEVERITY_LABEL[intel.severity] || '미확인'}`
      + (intel.cvss_vector ? ` (${intel.cvss_vector})` : '');
  }

  let epss = '미확인';
  if (intel.epss !== null && intel.epss !== undefined) {
    epss = intel.epss.toFixed(4)
      + (intel.epss_percentile != null ? ` · 백분위 ${intel.epss_percentile.toFixed(4)}` : '')
      + (intel.epss_snapshot_date ? ` · 기준일 ${intel.epss_snapshot_date}` : '');
  }

  let kev = '미확인';
  if (intel.kev === 'true') {
    kev = intel.kev_date_added ? `YES (등재 ${intel.kev_date_added})` : 'YES';
    if (String(intel.kev_ransomware_use || '').toLowerCase() === 'known') kev += ' · 랜섬웨어 사용 확인';
  } else if (intel.kev === 'false') kev = 'NO';

  let exploit = '미확인';
  if (intel.exploit_available === 'true') {
    const refs = (intel.exploit_sources || [])
      .map((s) => `${EXPLOIT_SOURCE_LABEL[s.source] || s.source} ${s.ref}`).join(', ');
    exploit = `YES (${MATURITY_LABEL[intel.exploit_maturity] || ''}${refs ? ` · ${refs}` : ''})`;
  } else if (intel.exploit_available === 'false') exploit = 'NO (조회한 공개 저장소 기준)';

  let verdictText = '';
  let policyText = '';
  if (verdict) {
    const level = engine.describeLevel(verdict.priority);
    const grounds = (verdict.fired_rules || []).map((r) => r.name).join(', ') || '기본 등급';
    verdictText = `${verdict.priority} ${level.label || ''} ← ${grounds}`;
    policyText = `${engine.sources.join('+')} v${verdict.policy_version} `
      + `(sha256:${String(verdict.policy_sha256 || '').slice(0, 12)})`;
  }

  return { cvss, epss, kev, exploit,
    fixed_version: finding.advisory?.fixed_version || '없음',
    verdict: verdictText, policy: policyText };
}

function buildReferences(finding) {
  const intel = finding.intel || {};
  const refs = [];
  const cve = intel.cve || '';

  if (cve.toUpperCase().startsWith('CVE-')) {
    refs.push({ source: 'NVD', title: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` });
    refs.push({ source: 'FIRST EPSS', title: `${cve} EPSS`,
      url: `https://api.first.org/data/v1/epss?cve=${cve}` });
  }
  if (intel.kev === 'true') {
    refs.push({ source: 'CISA KEV', title: 'Known Exploited Vulnerabilities Catalog',
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
  }
  for (const source of intel.exploit_sources || []) {
    let url = '';
    if (source.source === 'exploit_db' && String(source.ref).startsWith('EDB-')) {
      url = `https://www.exploit-db.com/exploits/${String(source.ref).slice(4)}`;
    } else if (source.source === 'metasploit') {
      url = 'https://github.com/rapid7/metasploit-framework';
    }
    refs.push({ source: EXPLOIT_SOURCE_LABEL[source.source] || source.source, title: source.ref, url });
  }
  for (const url of intel.references || []) {
    let label = 'Vendor Advisory';
    if (url.includes('nvd.nist.gov')) label = 'NVD';
    else if (url.includes('cisa.gov')) label = 'CISA';
    else if (url.includes('github.com/advisories')) label = 'GitHub Security Advisory';
    else if (url.includes('access.redhat.com')) label = 'Red Hat Advisory';
    refs.push({ source: label, title: url, url });
  }

  const seen = new Set();
  return refs.filter((r) => {
    const key = `${r.source}|${r.url || r.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildLocalAnalysis(finding) {
  const fix = finding.fix || {};
  const installed = finding.installed || {};
  const detection = finding.detection || {};
  return {
    ai_transmitted: false,
    installed_package: installed.name,
    installed_version: installed.version,
    package_type: installed.type,
    purl: installed.purl || '',
    locations: installed.locations || [],
    found_in_sbom: true,
    fix_analysis: {
      installed_version: fix.installed_version || '',
      fixed_version: fix.fixed_version || '',
      comparator: fix.comparator || '',
      is_vulnerable: fix.is_vulnerable || 'unknown',
      update_available: fix.update_available || 'unknown',
      fix_state: fix.fix_state || 'unknown',
      version_gap: fix.version_gap || 'unknown',
      reason: fix.reason || '',
    },
    detection: {
      matcher: detection.matcher || '',
      match_type: detection.match_type || '',
      namespace: detection.namespace || '',
      search_criteria: detection.search_criteria || {},
    },
  };
}

// --- 조립 -------------------------------------------------------------------

export function buildReport(scan, findings, { engine, playbooks, narratives = {} } = {}) {
  const sorted = [...findings].sort((a, b) => {
    const pa = priorityRank(a.verdict?.priority);
    const pb = priorityRank(b.verdict?.priority);
    if (pa !== pb) return pa - pb;
    const ca = a.intel?.cvss_score ?? 0;
    const cb = b.intel?.cvss_score ?? 0;
    if (ca !== cb) return cb - ca;
    return (a.intel?.cve || '').localeCompare(b.intel?.cve || '');
  });

  const items = sorted.map((finding) => {
    const [ruleText, preconditions, impacts] = ruleTechnicalRisk(finding);
    const ruleExploit = ruleExploitabilityNote(finding);
    const ruleRationale = ruleResponseRationale(finding, engine);
    const ai = narratives[finding.intel?.cve];
    const narrative = ai || {
      technical_risk: ruleText,
      attack_preconditions: preconditions,
      impact_types: impacts,
      exploitability_note: ruleExploit,
      response_rationale: ruleRationale,
      source: 'rule',
    };

    const verdict = finding.verdict || {};
    const priority = verdict.priority || 'P3';
    const level = engine.describeLevel(priority);
    const intel = finding.intel || {};
    const advisory = finding.advisory || {};

    return {
      cve: intel.cve,
      priority,
      priority_label: level.label || priority,
      aliases: intel.aliases || [],
      badge: buildBadge(finding, engine),
      overview: {
        cve: intel.cve,
        aliases: intel.aliases || [],
        advisory_package: advisory.advisory_package,
        advisory_ecosystem: advisory.advisory_ecosystem,
        affected_version_range: advisory.affected_version_range || '(범위 미공개)',
        fixed_version: advisory.fixed_version || '(없음)',
        fix_state: advisory.fix_state || 'unknown',
        severity: SEVERITY_LABEL[intel.severity] || '미확인',
        cvss_score: intel.cvss_score ?? null,
        cvss_vector: intel.cvss_vector || '',
        cvss_version: intel.cvss_version || '',
        cwe: (intel.cwe || []).map(cweLabel),
        published: intel.published || '',
        description: intel.description || '',
        os_family: advisory.os_family || '',
      },
      technical_risk: {
        narrative: narrative.technical_risk || ruleText,
        preconditions: narrative.attack_preconditions?.length ? narrative.attack_preconditions : preconditions,
        impact_types: narrative.impact_types?.length ? narrative.impact_types : impacts,
        cwe: (intel.cwe || []).map(cweLabel),
      },
      exploitability: {
        epss: intel.epss ?? null,
        epss_percentile: intel.epss_percentile ?? null,
        epss_snapshot_date: intel.epss_snapshot_date || '',
        kev: intel.kev || 'unknown',
        kev_date_added: intel.kev_date_added || '',
        kev_ransomware_use: intel.kev_ransomware_use || '',
        exploit_available: intel.exploit_available || 'unknown',
        exploit_maturity: intel.exploit_maturity || 'unknown',
        exploit_maturity_label: MATURITY_LABEL[intel.exploit_maturity] || '미확인',
        exploit_sources: (intel.exploit_sources || []).map((s) => ({
          source: s.source, label: EXPLOIT_SOURCE_LABEL[s.source] || s.source,
          ref: s.ref, note: s.note || '',
        })),
        published: intel.published || '',
        narrative: narrative.exploitability_note || ruleExploit,
      },
      response_rationale: {
        priority,
        priority_label: level.label || priority,
        priority_description: level.description || '',
        fired_rules: (verdict.fired_rules || []).map((r) => ({ name: r.name, explain: r.explain })),
        narrative: narrative.response_rationale || ruleRationale,
      },
      recommendation: playbooks.build({
        ecosystem: advisory.advisory_ecosystem || finding.installed?.type,
        packageName: advisory.advisory_package,
        installedVersion: finding.installed?.version,
        fixedVersion: advisory.fixed_version,
        cve: intel.cve,
        osFamily: advisory.os_family,
      }),
      references: buildReferences(finding),
      local_analysis: buildLocalAnalysis(finding),
      flags: (verdict.flags || []).map((name) => {
        const [label, note] = FLAG_INFO[name] || [name, ''];
        return { name, label, note };
      }),
      narrative_source: narrative.source || 'rule',
    };
  });

  return {
    generated_at: new Date().toISOString().replace(/\.\d+Z$/, '+00:00'),
    scan,
    summary: summarizeForReport(sorted, engine),
    findings: items,
    policy: {
      version: engine.version,
      sha256: engine.sha256,
      sources: engine.sources,
      label: `${engine.sources.join(' + ')} v${engine.version} (sha256:${String(engine.sha256).slice(0, 12)})`,
    },
    enrichment: scan.enrichment || {},
    disclaimer: DISCLAIMER,
    ai_used: items.some((i) => i.narrative_source === 'ai'),
  };
}

function summarizeForReport(findings, engine) {
  const byPriority = { P0: 0, P1: 0, P2: 0, P3: 0 };
  const labels = {};
  for (const p of ['P0', 'P1', 'P2', 'P3']) {
    byPriority[p] = findings.filter((f) => f.verdict?.priority === p).length;
    labels[p] = engine.describeLevel(p).label || p;
  }
  return {
    total: findings.length,
    by_priority: byPriority,
    priority_labels: labels,
    vulnerable_confirmed: findings.filter((f) => f.fix?.is_vulnerable === 'true').length,
    vulnerable_unconfirmed: findings.filter((f) => f.fix?.is_vulnerable === 'unknown').length,
    update_available: findings.filter((f) => f.fix?.update_available === 'true').length,
    no_fix_available: findings.filter((f) => f.verdict?.flags?.includes('no_fix_available')).length,
    kev_listed: findings.filter((f) => f.intel?.kev === 'true').length,
    exploit_available: findings.filter((f) => f.intel?.exploit_available === 'true').length,
    affected_packages: new Set(findings.map((f) => f.installed?.name)).size,
  };
}
