/**
 * 실 운영 스캔 제공자 — 로컬 FastAPI 서버를 호출한다.
 *
 * 진짜 Grype 서브프로세스가 돌아간다. GitHub Pages 데모는 같은 인터페이스를
 * 구현한 browser-engine.js를 대신 쓰며, 프론트엔드의 나머지 코드는 어느
 * 쪽인지 알지 못한다.
 */

const BASE = '';

async function request(path, options = {}) {
  const response = await fetch(BASE + path, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.detail) detail = body.detail;
    } catch { /* JSON이 아니면 상태 코드만 쓴다 */ }
    throw new Error(detail);
  }
  return response;
}

export const liveApiProvider = {
  name: 'live',
  label: '로컬 서버 (실제 Grype)',
  capabilities: { upload: true, enrich: true, persist: true, editor: false },

  async health() {
    return (await request('/api/health')).json();
  },

  async policy() {
    return (await request('/api/policy')).json();
  },

  async upload(file) {
    const form = new FormData();
    form.append('file', file);
    return (await request('/api/upload', { method: 'POST', body: form })).json();
  },

  async startScan({ uploadId, filename, enrich = true }) {
    const params = new URLSearchParams({
      upload_id: uploadId,
      filename: filename || '',
      enrich: String(enrich),
    });
    return (await request(`/api/scan?${params}`, { method: 'POST' })).json();
  },

  async pollScan(jobId) {
    return (await request(`/api/scan/${encodeURIComponent(jobId)}`)).json();
  },

  async getScan(scanId) {
    return (await request(`/api/scans/${encodeURIComponent(scanId)}`)).json();
  },

  async listScans() {
    return (await request('/api/scans')).json();
  },

  async getReport(scanId, format = 'json') {
    const response = await request(
      `/api/scans/${encodeURIComponent(scanId)}/report?format=${format}`,
    );
    return format === 'json' ? response.json() : response.text();
  },

  reportUrl(scanId, format) {
    return `/api/scans/${encodeURIComponent(scanId)}/report?format=${format}`;
  },
};
