/**
 * 이그레스 경계 (브라우저 구현) — core/vulnfact.py 의 동형.
 *
 * 거르기가 아니라 조립이다. Finding 전체를 받지 않고 공개 계층 두 개만 받는다.
 * 인자 이름이 곧 계약이며, 로컬 계층을 넘기려면 시그니처를 고쳐야 한다.
 */

const ALLOWED_EXPLOIT_SOURCES = new Set(['exploit_db', 'metasploit', 'github_poc', 'nuclei']);

/** 공개 계층 두 개에서만 VulnFact를 조립한다. */
export function buildVulnFact(advisory, intel) {
  return {
    cve: intel.cve,
    cvss_score: intel.cvss_score ?? null,
    cvss_vector: intel.cvss_vector || '',
    cvss_version: intel.cvss_version || '',
    severity: intel.severity || 'unknown',
    cwe: [...(intel.cwe || [])],
    published: intel.published || '',

    epss: intel.epss ?? null,
    epss_percentile: intel.epss_percentile ?? null,
    epss_snapshot_date: intel.epss_snapshot_date || '',
    kev: intel.kev || 'unknown',
    kev_date_added: intel.kev_date_added || '',
    kev_ransomware_use: intel.kev_ransomware_use || '',
    exploit_available: intel.exploit_available || 'unknown',
    exploit_maturity: intel.exploit_maturity || 'unknown',
    // 저장소가 채운 자유 텍스트(note)는 무엇이 들어 있을지 보장할 수 없다.
    exploit_sources: (intel.exploit_sources || [])
      .filter((s) => ALLOWED_EXPLOIT_SOURCES.has(s.source))
      .map((s) => ({ source: s.source, ref: s.ref })),

    // 아래는 전부 advisory가 공표한 값이지 우리 자산의 사실이 아니다.
    advisory_package: advisory.advisory_package,
    advisory_ecosystem: advisory.advisory_ecosystem || '',
    affected_version_range: advisory.affected_version_range || '',
    fixed_version: advisory.fixed_version || '',
    os_family: advisory.os_family || '',
  };
}

/** Finding에서 공개 계층만 꺼내 넘긴다. 본문이 한 줄인 데 이유가 있다. */
export function buildFromFinding(finding) {
  return buildVulnFact(finding.advisory, finding.intel);
}

/**
 * 여러 Finding을 VulnFact 목록으로. 같은 CVE·패키지는 한 번만 나간다 —
 * 중복 건수는 곧 '우리 환경에 몇 대나 있는가'라는 내부 정보다.
 */
export function buildBatch(findings) {
  const seen = new Set();
  const facts = [];
  for (const f of findings) {
    const key = `${f.intel?.cve}|${f.advisory?.advisory_package}|${f.advisory?.advisory_ecosystem}`;
    if (seen.has(key)) continue;
    seen.add(key);
    facts.push(buildFromFinding(f));
  }
  return facts;
}
