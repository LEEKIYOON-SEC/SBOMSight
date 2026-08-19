/**
 * SBOM 파싱 — core/sbom.py 의 동형 구현.
 *
 * 여기서 나오는 것은 전부 로컬 전용 계층(InstalledPackage)이다. 브라우저
 * 데모에서도 SBOM은 방문자의 파일이며 어디로도 올라가지 않는다 —
 * 파싱부터 매칭까지 전부 브라우저 안에서 끝난다.
 */

const PURL_RE = /^pkg:([^/]+)\/([^?#]+?)(?:@([^?#]+))?(?:[?#].*)?$/;
const SYFT_TYPE_PROP = 'syft:package:type';
const SYFT_LOCATION_RE = /^syft:location:\d+:path$/;

const PURL_TYPE_ALIAS = {
  pypi: 'python',
  golang: 'go-module',
  cargo: 'rust-crate',
  maven: 'java-archive',
  composer: 'php-composer',
  rubygems: 'gem',
};

export function fromPurl(purl) {
  const m = PURL_RE.exec(String(purl || '').trim());
  if (!m) return ['', '', ''];
  const type = m[1].toLowerCase();
  const name = m[2].split('/').pop();
  return [PURL_TYPE_ALIAS[type] || type, name, m[3] || ''];
}

export function detectFormat(payload) {
  if (!payload || typeof payload !== 'object') return 'unknown';
  if (payload.bomFormat === 'CycloneDX' || ('components' in payload && 'specVersion' in payload))
    return 'cyclonedx-json';
  if (payload.spdxVersion || 'SPDXID' in payload) return 'spdx-json';
  if ('artifacts' in payload && 'descriptor' in payload) return 'syft-json';
  return 'unknown';
}

function parseCycloneDx(payload) {
  const packages = [];
  for (const comp of payload.components || []) {
    if (!comp || typeof comp !== 'object') continue;
    const purl = String(comp.purl || '');
    const [typePurl, namePurl, versionPurl] = fromPurl(purl);

    const props = {};
    const locations = [];
    for (const prop of comp.properties || []) {
      if (!prop || typeof prop !== 'object') continue;
      const key = String(prop.name || '');
      const value = String(prop.value || '');
      props[key] = value;
      if (SYFT_LOCATION_RE.test(key) && value) locations.push(value);
    }

    const name = String(comp.name || '') || namePurl;
    if (!name) continue;
    packages.push({
      name,
      version: String(comp.version || '') || versionPurl,
      type: props[SYFT_TYPE_PROP] || typePurl,
      purl,
      cpes: comp.cpe ? [String(comp.cpe)] : [],
      locations,
      language: '',
      sbom_ref: String(comp['bom-ref'] || ''),
    });
  }
  return packages;
}

function parseSpdx(payload) {
  const packages = [];
  for (const pkg of payload.packages || []) {
    if (!pkg || typeof pkg !== 'object') continue;
    let purl = '';
    const cpes = [];
    for (const ref of pkg.externalRefs || []) {
      if (!ref || typeof ref !== 'object') continue;
      const refType = String(ref.referenceType || '').toLowerCase();
      const locator = String(ref.referenceLocator || '');
      if (refType === 'purl' && !purl) purl = locator;
      else if (refType.startsWith('cpe')) cpes.push(locator);
    }
    const [type, namePurl, versionPurl] = fromPurl(purl);
    const name = String(pkg.name || '') || namePurl;
    const version = String(pkg.versionInfo || '') || versionPurl;
    if (!name || name === 'NOASSERTION') continue;
    packages.push({
      name,
      version: version === 'NOASSERTION' ? '' : version,
      type, purl, cpes, locations: [], language: '',
      sbom_ref: String(pkg.SPDXID || ''),
    });
  }
  return packages;
}

function parseSyft(payload) {
  const packages = [];
  for (const art of payload.artifacts || []) {
    if (!art || typeof art !== 'object') continue;
    const name = String(art.name || '');
    if (!name) continue;
    packages.push({
      name,
      version: String(art.version || ''),
      type: String(art.type || ''),
      purl: String(art.purl || ''),
      cpes: (art.cpes || []).map(String),
      locations: (art.locations || [])
        .filter((l) => l && l.path).map((l) => String(l.path)),
      language: String(art.language || ''),
      sbom_ref: String(art.id || ''),
    });
  }
  return packages;
}

/** SBOM 문서에서 [형식, 설치 패키지 목록]을 뽑는다. */
export function parseSbom(payload) {
  const format = detectFormat(payload);
  if (format === 'cyclonedx-json') return [format, parseCycloneDx(payload)];
  if (format === 'spdx-json') return [format, parseSpdx(payload)];
  if (format === 'syft-json') return [format, parseSyft(payload)];
  return [format, []];
}

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
