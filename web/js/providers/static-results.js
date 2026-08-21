/**
 * 정적 결과 전시 제공자 — GitHub Pages 용.
 *
 * Pages에서는 스캔하지 않는다. Grype는 Go 바이너리와 수백 MB짜리 취약점
 * DB를 요구하고, AI 호출에 쓰는 키는 정적 페이지에 담을 수 없다. 브라우저에
 * 두 번째 매칭 엔진을 두는 방법도 써 봤지만 배포판 네임스페이스를 뭉개
 * 틀린 판정을 냈다. 그래서 여기서는 아무것도 계산하지 않는다.
 *
 * 대신 실제 PC에서 진짜 Syft/Grype로 돌린 결과를 통째로 내보내
 * (`python -m core.cli export`) 그것을 같은 UI로 그려 준다. 화면에 보이는
 * 판정·전송 내역·보고서는 전부 그때 실제로 일어난 일의 기록이다.
 *
 *   results/index.json              공개된 스캔 목록
 *   results/<scan_id>/scan.json     탐지 결과 (/api/scans/{id} 와 같은 모양)
 *   results/<scan_id>/report.json   보고서
 *   results/<scan_id>/report.md     보고서 Markdown
 *   results/<scan_id>/egress.json   실제로 AI에 전송된 내용 기록
 */

const ROOT = 'results';

const cache = new Map();

async function loadJson(path) {
  if (cache.has(path)) return cache.get(path);
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${path} 를 불러오지 못했습니다 (${response.status})`);
  }
  const data = await response.json();
  cache.set(path, data);
  return data;
}

function scanDir(scanId) {
  return `${ROOT}/${encodeURIComponent(scanId)}`;
}

export const staticResultsProvider = {
  name: 'static',
  label: '전시 모드 (실제 PC에서 뽑은 결과)',
  // 업로드도 AI 호출도 없다. UI가 해당 조작을 아예 감추도록 알려 준다.
  capabilities: { upload: false, enrich: false, persist: false, ai: false, select: false },
  readonly: true,

  async health() {
    const index = await loadJson(`${ROOT}/index.json`);
    return {
      ok: true,
      mode: 'static',
      tools: index.tools || {},
      exported_at: index.generated_at || '',
      scan_count: (index.scans || []).length,
      ai: { enabled: false, ready: false },
      note: (
        '이 페이지는 실제 PC에서 진짜 Syft/Grype로 수행한 결과를 전시합니다. '
        + '브라우저에서는 스캔도 AI 호출도 하지 않습니다.'
      ),
    };
  },

  async listScans() {
    const index = await loadJson(`${ROOT}/index.json`);
    return { scans: index.scans || [] };
  },

  async getScan(scanId) {
    return loadJson(`${scanDir(scanId)}/scan.json`);
  },

  async getReport(scanId, format = 'json') {
    if (format === 'json') return loadJson(`${scanDir(scanId)}/report.json`);
    const response = await fetch(`${scanDir(scanId)}/report.${format === 'markdown' ? 'md' : format}`);
    if (!response.ok) throw new Error(`보고서를 불러오지 못했습니다 (${response.status})`);
    return response.text();
  },

  reportUrl(scanId, format) {
    if (format === 'markdown') return `${scanDir(scanId)}/report.md`;
    if (format === 'html') return `${scanDir(scanId)}/report.html`;
    return `${scanDir(scanId)}/report.json`;
  },

  /**
   * 실제로 전송된 내용의 기록. 여기서 다시 조립하지 않는다 — 조립기를
   * 브라우저에 한 벌 더 두면 전시된 내용과 실제로 나간 내용이 갈라진다.
   */
  async egressPreview(scanId) {
    const record = await loadJson(`${scanDir(scanId)}/egress.json`);
    return { ...record, recorded: true };
  },
};
