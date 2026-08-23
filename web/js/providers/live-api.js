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

/** 세션이 만료되면 화면 어디에 있든 로그인으로 보낸다.
 *
 * 12시간짜리 세션이라 화면을 열어 둔 채 다음 날 조작하는 일이 흔하다. 그때
 * "401 Unauthorized" 라는 문자열만 뜨면 무엇을 해야 하는지 알 수 없다.
 */
function toLogin() {
  const here = window.location.pathname.replace(/^\//, '') + window.location.search;
  window.location.replace(`login.html?next=${encodeURIComponent(here || 'index.html')}`);
}

async function request(path, options = {}) {
  const response = await fetch(BASE + path, options);
  if (!response.ok) {
    if (response.status === 401 && !window.location.pathname.endsWith('login.html')) {
      toLogin();
    }
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

  /**
   * SBOM 업로드.
   *
   * multipart 를 쓰지 않는다. Starlette 의 multipart 파서는 파트 하나를 1MB로
   * 제한하고 서버 쪽에서 그 값을 올릴 방법이 없다 — 실 서버 SBOM 은 100MB를
   * 넘으므로 그 경로로는 애초에 올라가지 않았다. 본문에 파일을 그대로 싣는다.
   *
   * fetch 대신 XHR 을 쓰는 이유는 하나뿐이다: fetch 는 업로드 진행률을 주지
   * 않는다. 100MB를 올리는 동안 화면이 멈춘 것처럼 보이면 안 된다.
   */
  upload(file, { onProgress } = {}) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${BASE}api/upload?filename=${encodeURIComponent(file.name)}`);
      xhr.setRequestHeader('Content-Type', 'application/json');

      if (onProgress) {
        xhr.upload.addEventListener('progress', (event) => {
          if (event.lengthComputable) onProgress(event.loaded, event.total);
        });
      }

      xhr.addEventListener('load', () => {
        let body = null;
        try { body = JSON.parse(xhr.responseText); } catch { /* 아래에서 처리 */ }
        if (xhr.status >= 200 && xhr.status < 300 && body) resolve(body);
        else reject(new Error(body?.detail || `${xhr.status} ${xhr.statusText}`));
      });
      xhr.addEventListener('error', () => reject(new Error('업로드 중 연결이 끊겼습니다.')));
      xhr.addEventListener('abort', () => reject(new Error('업로드가 취소되었습니다.')));

      xhr.send(file);
    });
  },

  async startScan({ uploadId, filename, enrich = true, assetId = '' }) {
    const params = new URLSearchParams({
      upload_id: uploadId,
      filename: filename || '',
      enrich: String(enrich),
      asset_id: assetId || '',
    });
    return (await request(`api/scan?${params}`, { method: 'POST' })).json();
  },

  async pollScan(jobId) {
    return (await request(`api/scan/${encodeURIComponent(jobId)}`)).json();
  },

  async getScan(scanId) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}`)).json();
  },

  /**
   * 결과 한 페이지.
   *
   * 서버 한 대가 48,923건을 낸다. 전부 내려받으면 82MB 이고, 브라우저는 그것을
   * 파싱한 뒤 DOM 노드 40만 개를 만들다가 멈춘다. 정렬·필터·페이징을 전부
   * 서버(SQL)가 하고 여기서는 100건만 받는다.
   */
  async listFindings(scanId, params = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) query.set(key, String(value));
    }
    return (await request(`api/scans/${encodeURIComponent(scanId)}/findings?${query}`)).json();
  },

  /** 스캔 머리말(메타·정책·보강 상태). findings 는 들어 있지 않다. */
  async getScanMeta(scanId) {
    const scan = await (await request(`api/scans/${encodeURIComponent(scanId)}/meta`)).json();
    return scan;
  },

  /**
   * 조치 대상 한 쪽. **패키지 하나가 한 줄이다.**
   *
   * 48,923건은 패키지 8,154개가 된다. 그것도 한 화면에 그릴 양이 아니다.
   */
  async listPackages(scanId, params = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) query.set(key, String(value));
    }
    return (await request(`api/scans/${encodeURIComponent(scanId)}/packages?${query}`)).json();
  },

  /** 지금 조건에 맞는 묶음 키 전부. "전체 선택" 이 쓴다. 상한은 없다. */
  async packageKeys(scanId, params = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) query.set(key, String(value));
    }
    return (await request(`api/scans/${encodeURIComponent(scanId)}/package-keys?${query}`)).json();
  },

  /**
   * 묶음 하나에 속한 취약점 목록. 표에서 패키지를 눌렀을 때만 부른다.
   *
   * 패키지 이름은 **쿼리로 보낸다.** 경로에 실으면 이름에 `/` 가 들어가는
   * 패키지가 404 가 된다 — Go 모듈(`github.com/gogo/protobuf`)과 npm 스코프
   * (`@babel/core`) 가 전부 그렇다.
   */
  async packageFindings(scanId, pkg, version = '') {
    const query = new URLSearchParams({ name: pkg, limit: '500' });
    if (version) query.set('version', version);
    const page = await (await request(
      `api/scans/${encodeURIComponent(scanId)}/package/findings?${query}`,
    )).json();
    return page.findings || [];
  },

  /** 묶음 하나의 상세. 펼쳤을 때만 부른다. */
  async packageDetail(scanId, pkg, { version = '', ai = false } = {}) {
    const query = new URLSearchParams({ name: pkg, ai: String(Boolean(ai)) });
    if (version) query.set('version', version);
    return (await request(`api/scans/${encodeURIComponent(scanId)}/package?${query}`)).json();
  },

  /** 기록된 선택 키. 되살리려고 스캔 전체를 받지 않는다. */
  async getSelection(scanId) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}/selection`)).json();
  },

  /** 요약 타일 값. 세려고 전체를 내려받지 않는다. */
  async scanSummary(scanId) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}/summary`)).json();
  },

  /** 지금 필터에 맞는 선택 키 전부. "필터 전체 선택" 이 쓴다. */
  async findingKeys(scanId, params = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) query.set(key, String(value));
    }
    return (await request(`api/scans/${encodeURIComponent(scanId)}/finding-keys?${query}`)).json();
  },

  /** 항목 하나의 상세(보고서 절·권고 절차). 그 한 건만 조립해 온다. */
  async findingDetail(scanId, key) {
    return (await request(
      `api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(key)}`,
    )).json();
  },

  /** 지금 필터에 맞는 항목 전부를 CSV 로. 서버가 청크로 흘려 보낸다. */
  csvUrl(scanId, params = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) query.set(key, String(value));
    }
    return `api/scans/${encodeURIComponent(scanId)}/findings.csv?${query}`;
  },

  async listScans() {
    return (await request('api/scans')).json();
  },

  /**
   * 보고서.
   *
   * `ai=false` 는 만들어 둔 AI 서술까지 빼고 뽑는다. 결재 문서를 AI 없이 내야
   * 하는 경우가 있고, 그때는 AI 관련 문구가 한 줄도 없어야 한다.
   */
  async getReport(scanId, format = 'json', { selection = [], ai = false } = {}) {
    const params = selectionParams(selection);
    params.set('format', format);
    params.set('ai', String(Boolean(ai)));
    const response = await request(`api/scans/${encodeURIComponent(scanId)}/report?${params}`);
    return format === 'json' ? response.json() : response.text();
  },

  reportUrl(scanId, format, {
    selection = [], saved = false, ai = false, package: pkg = '', version = '', cve = '',
  } = {}) {
    const params = saved ? new URLSearchParams({ saved: 'true' }) : selectionParams(selection);
    params.set('format', format);
    params.set('ai', String(Boolean(ai)));
    // 패키지를 지정하면 그 묶음만 담긴다. 48,923건짜리 문서를 만들어 그중
    // 한 절만 읽을 이유가 없다.
    if (pkg) params.set('package', pkg);
    if (version) params.set('version', version);
    // CVE 하나만. 근거 팝업이 쓴다 — 6건짜리 패키지 문서를 받아 그중 한 절만
    // 읽을 이유가 없다.
    if (cve) params.set('cve', cve);
    return `api/scans/${encodeURIComponent(scanId)}/report?${params}`;
  },

  /** 연계 분석에서 전송될 내용 전체. 이 호출은 외부로 아무것도 보내지 않는다. */
  async chainsPreview(scanId, { selection = [], saved = false } = {}) {
    const params = saved ? new URLSearchParams({ saved: 'true' }) : selectionParams(selection);
    const query = params.toString();
    return (await request(
      `api/scans/${encodeURIComponent(scanId)}/chains/preview${query ? `?${query}` : ''}`,
    )).json();
  },

  /** 패키지 묶음별 연계 분석을 생성한다. 같은 가드를 통과한 VulnFact 만 나간다. */
  async generateChains(scanId, { selection = [], saved = false } = {}) {
    return (await request(`api/scans/${encodeURIComponent(scanId)}/chains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(saved ? { saved: true } : { selection }),
    })).json();
  },

  /**
   * AI에게 전송될 내용 전체. 실제 전송에 쓰이는 것과 같은 조립기·같은 가드를
   * 통과시킨 결과를 돌려주며, 이 호출 자체는 외부로 아무것도 보내지 않는다.
   * 선택한 항목만 넘기면 그 항목분만 조립된다.
   */
  async egressPreview(scanId, { selection = [], saved = false } = {}) {
    // 저장된 선택을 가리킨다. 고른 키를 전부 주소창에 실으면 5,000건에서
    // URL 이 250KB 가 되고 HTTP 파서가 요청을 끊는다.
    const params = saved ? new URLSearchParams({ saved: 'true' }) : selectionParams(selection);
    const query = params.toString();
    return (await request(
      `api/scans/${encodeURIComponent(scanId)}/egress/preview${query ? `?${query}` : ''}`,
    )).json();
  },

  async egressPolicy() {
    return (await request('api/egress/policy')).json();
  },

  /**
   * 담당자가 고른 항목을 서버에 기록한다. 보고서를 열 때마다 범위를 다시
   * 고르지 않아도 되고, `core.cli export` 가 "이 보고서는 무엇을 대상으로
   * 만들어졌는가"를 그대로 옮길 수 있다.
   */
  async saveSelection(scanId, body) {
    // 패키지로 고르면 `{ packages: [...] }`, finding 키로 고르면
    // `{ selection: [...] }`. 화면은 패키지를 고른다.
    const payload = Array.isArray(body) ? { selection: body } : body;
    return (await request(`api/scans/${encodeURIComponent(scanId)}/selection`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })).json();
  },

  /**
   * 선택한 항목에 대해서만 AI 서술을 생성한다.
   *
   * 키는 서버 환경변수에 있고 브라우저로 내려오지 않는다. 전송되는 내용은
   * egressPreview가 보여 준 것과 **같은 조립기·같은 가드**를 통과한 결과이며,
   * 가드가 막으면 호출 자체가 일어나지 않는다.
   */
  async generateNarratives(scanId, { package: pkg, version = '' } = {}) {
    // **패키지 하나씩.** 범위를 넓게 잡으면 분당 토큰 한도를 첫 요청에서 넘겨
    // 그 뒤가 전부 실패한다 — 생성해도 달라지는 것이 없었던 이유가 그것이다.
    return (await request(`api/scans/${encodeURIComponent(scanId)}/narratives`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: pkg, version }),
    })).json();
  },
};
