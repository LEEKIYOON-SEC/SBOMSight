/**
 * 실 운영 스캔 제공자 — 로컬 FastAPI 서버를 호출한다.
 *
 * 진짜 Syft/Grype 서브프로세스가 돌아간다. 취약점 판정도, 이그레스 가드도,
 * AI 호출도 전부 서버에서 일어난다. 브라우저는 결과를 그리고 사람이 무엇을
 * 보낼지 고르게 할 뿐이며, API 키는 브라우저로 내려오지 않는다.
 */

// 페이지가 사이트 루트에 있으므로 상대 경로가 로컬 서버와 정적 배포 양쪽에서
// 올바르게 풀린다. 절대 경로(/api/...)를 쓰면 GitHub Pages의 프로젝트 하위
// 경로(/SBOMSight/)에서 도메인 루트를 가리켜 깨진다.
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

/** 선택한 finding 키들을 쿼리스트링으로 옮긴다. 빈 배열이면 전체를 뜻한다. */
function selectionParams(selection) {
  const params = new URLSearchParams();
  for (const key of selection || []) params.append('select', key);
  return params;
}

export const liveApiProvider = {
  name: 'live',
  label: '로컬 서버 (실제 Grype)',
  capabilities: { upload: true, enrich: true, persist: true, ai: true },

  async health() {
    return (await request('api/health')).json();
  },

  async policy() {
    return (await request('api/policy')).json();
  },

  async upload(file) {
    const form = new FormData();
    form.append('file', file);
    return (await request('api/upload', { method: 'POST', body: form })).json();
  },

  async startScan({ uploadId, filename, enrich = true }) {
    const params = new URLSearchParams({
      upload_id: uploadId,
      filename: filename || '',
      enrich: String(enrich),
    });
    return (await request(`api/scan?${params}`, { method: 'POST' })).json();
  },

  async pollScan(jobId) {
    return (await request(`api/scan/${encodeURIComponent(jobId)}`)).json();
  },

  async getScan(scanId) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}`)).json();
  },

  async listScans() {
    return (await request('api/scans')).json();
  },

  async getReport(scanId, format = 'json', { selection = [] } = {}) {
    const params = selectionParams(selection);
    params.set('format', format);
    const response = await request(`api/scans/${encodeURIComponent(scanId)}/report?${params}`);
    return format === 'json' ? response.json() : response.text();
  },

  reportUrl(scanId, format, { selection = [] } = {}) {
    const params = selectionParams(selection);
    params.set('format', format);
    return `api/scans/${encodeURIComponent(scanId)}/report?${params}`;
  },

  /**
   * AI에게 전송될 내용 전체. 실제 전송에 쓰이는 것과 같은 조립기·같은 가드를
   * 통과시킨 결과를 돌려주며, 이 호출 자체는 외부로 아무것도 보내지 않는다.
   * 선택한 항목만 넘기면 그 항목분만 조립된다.
   */
  async egressPreview(scanId, { selection = [] } = {}) {
    const params = selectionParams(selection);
    const query = params.toString();
    return (await request(
      `api/scans/${encodeURIComponent(scanId)}/egress/preview${query ? `?${query}` : ''}`,
    )).json();
  },

  async egressPolicy() {
    return (await request('api/egress/policy')).json();
  },

  /**
   * 선택한 항목에 대해서만 AI 서술을 생성한다.
   *
   * 키는 서버 환경변수에 있고 브라우저로 내려오지 않는다. 전송되는 내용은
   * egressPreview가 보여 준 것과 **같은 조립기·같은 가드**를 통과한 결과이며,
   * 가드가 막으면 호출 자체가 일어나지 않는다.
   */
  async generateNarratives(scanId, { selection = [] } = {}) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}/narratives`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selection }),
    })).json();
  },
};
