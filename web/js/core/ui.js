/** 공용 DOM 렌더링 헬퍼. */

import {
  EXPLOIT_SOURCE_LABEL, FIX_STATE_LABEL, PRIORITIES,
  PRIORITY_LABEL, SEVERITY_LABEL, TERNARY_LABEL,
  describeFlag, formatCvss, formatEpss, formatExploit, formatKev,
} from './model.js';
import { formatProbability } from './format.js';

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** 사용자·외부 데이터가 마크업으로 해석되지 않게 막는다. */
export function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function el(html) {
  const template = document.createElement('template');
  template.innerHTML = html.trim();
  return template.content.firstElementChild;
}

/**
 * 대응 검토 등급.
 *
 * `P0` 같은 코드는 붙이지 않는다 — 뜻이 없는 글자를 매번 되짚게 만든다.
 * 표에서는 배지가 아니라 **행 왼쪽의 색 띠**로 낸다. 등급은 배지 하나가 아니라
 * 그 행의 성격이고, 배지로 두면 KEV·Exploit 배지와 한 칸에 뭉쳐 서로를 가린다.
 */
export function priorityPill(priority) {
  const p = PRIORITIES.includes(priority) ? priority : 'P3';
  return `<span class="pill ${p.toLowerCase()}">${esc(PRIORITY_LABEL[p])}</span>`;
}

export function priorityMark(priority) {
  const p = PRIORITIES.includes(priority) ? priority : 'P3';
  return `<span class="mark ${p.toLowerCase()}"></span>${esc(PRIORITY_LABEL[p])}`;
}

/**
 * 근거 — **참인 신호만** 최대 두 개.
 *
 * 예전에는 KEV·Exploit·수정본없음·미확인N 을 모두 한 칸에 쌓아 배지가 겹쳤다.
 * 값이 없다는 뜻의 '미확인'까지 배지로 붙으면 실제 위험 신호가 묻힌다.
 * 나머지는 상세에 있다.
 */
export function evidenceCell(finding) {
  const intel = finding.intel || {};
  const marks = [];
  if (intel.kev === 'true') marks.push('<span class="tag danger">실제 악용</span>');
  if (intel.exploit_available === 'true') marks.push('<span class="tag warn">공격코드 공개</span>');
  if (marks.length < 2 && (finding.verdict?.flags || []).includes('no_fix_available')) {
    marks.push('<span class="tag">수정본 없음</span>');
  }
  return marks.slice(0, 2).join(' ') || '<span class="faint">—</span>';
}

/**
 * 설치 → 수정. 조치를 한 칸에서 읽는다.
 *
 * `없음` 은 수정본이 나오지 않았다는 뜻(완화 방안이 필요하다),
 * `확인 필요` 는 Grype 가 수정 상태를 판단하지 못했다는 뜻이다. 둘을 같은
 * 빈칸으로 두면 "패치할 게 없다"와 "모른다"가 구분되지 않는다.
 */
export function fixCell(finding) {
  const fix = finding.fix || {};
  const installed = fix.installed_version || finding.installed?.version || '—';
  const state = fix.fix_state;
  let target;
  if (fix.fixed_version) target = `<b class="mono">${esc(fix.fixed_version)}</b>`;
  else if (state === 'not_fixed' || state === 'wont_fix') target = '<span class="none">없음</span>';
  else target = '<span class="faint">확인 필요</span>';
  return `<span class="mono">${esc(installed)}</span> <span class="arrow">→</span> ${target}`;
}

export function renderStepper(container, steps) {
  container.innerHTML = steps
    .map(
      (s) => `
      <div class="step" data-state="${esc(s.state)}" data-key="${esc(s.key)}">
        <div class="label"><span class="dot"></span>${esc(s.label)}</div>
        <div class="metric">${esc(s.metric || (s.state === 'running' ? '…' : '—'))}</div>
        <div class="detail">${esc(s.detail || '')}</div>
      </div>`,
    )
    .join('');
}

export function renderStats(container, summary) {
  const tiles = PRIORITIES.map(
    (p) => `<div class="stat ${p.toLowerCase()}">
        <div class="n">${summary.by_priority[p] ?? 0}</div>
        <div class="k">${esc(PRIORITY_LABEL[p])}</div>
      </div>`,
  );
  tiles.push(`<div class="stat">
      <div class="n">${summary.total}</div>
      <div class="k">전체 탐지</div>
    </div>`);
  container.innerHTML = tiles.join('');
}

/**
 * 요약 줄.
 *
 * "취약 확인 / 판단 불가"를 뺐다. 표에 있는 것은 전부 Grype 가 취약하다고 탐지한
 * 것이므로 "취약 확인 N건"은 "전체 N건"의 재진술이었고, "판단 불가"는 우리
 * 비교자가 못 읽었다는 뜻이 Grype 판정에 대한 의심으로 읽히던 자리였다.
 */
export function renderSummaryLine(container, summary) {
  container.innerHTML = `
    <span>영향 패키지 <b>${summary.affected_packages}</b>개</span>
    <span class="arrow">·</span>
    <span>업데이트 가능 <b>${summary.update_available}</b>건</span>
    <span class="arrow">·</span>
    <span>수정 버전 없음 <b>${summary.no_fix_available}</b>건</span>
    <span class="arrow">·</span>
    <span>실제 악용 확인 <b>${summary.kev_listed}</b>건</span>
    <span class="arrow">·</span>
    <span>공격코드 공개 <b>${summary.exploit_available}</b>건</span>`;
}

/**
 * 결과 표.
 *
 * 각 행에 체크박스가 붙는다 — 보고서와 AI 전송의 범위를 담당자가 직접 고른다.
 * 체크박스를 누르는 것과 행을 눌러 상세를 여는 것은 다른 동작이므로, 체크박스
 * 열에서 일어난 클릭은 드로어를 열지 않는다.
 *
 * @param {(f) => string}   key       선택 키를 만드는 함수
 * @param {Set<string>}     selected  현재 선택된 키
 * @param {(key, on) => void} onToggle  체크 상태가 바뀌었을 때
 * @param {boolean}         selectable 전시 모드에서는 false — 기록된 선택만 보여 준다
 */
export function renderTable(tbody, findings, onSelect, {
  key = () => '', selected = new Set(), onToggle = null, selectable = true,
} = {}) {
  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:2rem">
      조건에 맞는 항목이 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = findings
    .map((f, index) => {
      const intel = f.intel || {};
      const priority = (PRIORITIES.includes(f.verdict?.priority) ? f.verdict.priority : 'P3');
      const k = key(f);
      const checked = selected.has(k) ? 'checked' : '';
      return `
      <tr class="clickable row-${priority.toLowerCase()}" data-index="${index}">
        <td class="pick"><input type="checkbox" data-key="${esc(k)}" ${checked}
          ${selectable ? '' : 'disabled'} aria-label="보고서 대상으로 선택"></td>
        <td class="review">${priorityMark(f.verdict?.priority)}</td>
        <td><b class="mono">${esc(intel.cve)}</b></td>
        <td>${esc(f.installed?.name)}</td>
        <td class="fix">${fixCell(f)}</td>
        <td class="num">${intel.cvss_score ?? '<span class="faint">—</span>'}</td>
        <td class="num">${esc(formatEpss(intel) === '미확인' ? '—' : formatEpss(intel))}</td>
        <td>${evidenceCell(f)}</td>
      </tr>`;
    })
    .join('');

  tbody.querySelectorAll('tr.clickable').forEach((row) => {
    row.addEventListener('click', (event) => {
      // 체크박스 열은 선택 조작 전용이다. 여기서 드로어까지 열리면
      // 몇 건을 고르는 동안 상세 패널이 계속 튀어나온다.
      if (event.target.closest('.pick')) return;
      onSelect(findings[Number(row.dataset.index)]);
    });
  });

  if (!selectable || !onToggle) return;
  tbody.querySelectorAll('.pick input[type=checkbox]').forEach((box) => {
    box.addEventListener('change', () => onToggle(box.dataset.key, box.checked));
  });
}

/**
 * 결과 표 한 줄 = **패키지 하나**.
 *
 * 조치는 패키지당 한 번이다 — `openssl` 을 3.0.7로 올리면 CVE 5건이 한 번에
 * 해소되는데, CVE 단위로 늘어놓으면 같은 패치를 5번 읽게 된다. 48,923건이
 * 8,154줄이 되고, 고르는 단위도 인쇄하는 단위도 그것과 같아진다.
 */
export function renderPackageTable(tbody, groups, onOpen, {
  selected = new Set(), onToggle = null, selectable = true,
} = {}) {
  if (!groups.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:2rem">
      조건에 맞는 패키지가 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = groups.map((g, index) => {
    const priority = PRIORITIES.includes(g.priority) ? g.priority : 'P3';
    const checked = selected.has(g.key) ? 'checked' : '';
    const target = g.target_version
      ? `<b class="mono">${esc(g.target_version)}</b>`
      : '<span class="none">없음</span>';
    const marks = [];
    if (g.kev_count) marks.push('<span class="tag danger">실제 악용</span>');
    if (g.exploit_count) marks.push('<span class="tag warn">공격코드 공개</span>');
    if (marks.length < 2 && g.no_fix_count) marks.push('<span class="tag">수정본 없음</span>');
    return `
    <tr class="clickable row-${priority.toLowerCase()}" data-index="${index}">
      <td class="pick"><input type="checkbox" data-key="${esc(g.key)}" ${checked}
        ${selectable ? '' : 'disabled'} aria-label="보고서 대상으로 선택"></td>
      <td class="review">${priorityMark(g.priority)}</td>
      <td><b>${esc(g.package)}</b> <span class="faint">${esc(g.package_type)}</span></td>
      <td class="fix"><span class="mono">${esc(g.installed_version)}</span>
        <span class="arrow">→</span> ${target}</td>
      <td class="num">${g.cve_count.toLocaleString()}</td>
      <td class="num">${g.max_cvss ?? '<span class="faint">—</span>'}</td>
      <td class="num">${esc(formatProbability(g.max_epss))}</td>
      <td>${marks.slice(0, 2).join(' ') || '<span class="faint">—</span>'}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('tr.clickable').forEach((row) => {
    row.addEventListener('click', (event) => {
      if (event.target.closest('.pick')) return;
      onOpen(groups[Number(row.dataset.index)]);
    });
  });

  if (!selectable || !onToggle) return;
  tbody.querySelectorAll('.pick input[type=checkbox]').forEach((box) => {
    box.addEventListener('change', () => onToggle(box.dataset.key, box.checked));
  });
}

/** 묶음을 펼쳤을 때 나오는 CVE 목록. 카드가 아니라 **줄**이다. */
export function renderCveList(host, findings, onOpen) {
  host.innerHTML = `<table class="cve-list"><thead><tr>
      <th>대응 검토</th><th>CVE</th><th class="num">심각도</th>
      <th class="num">악용 예측</th><th>수정 버전</th><th>근거</th>
    </tr></thead><tbody>${findings.map((f, index) => {
      const intel = f.intel || {};
      const fix = f.fix || {};
      const priority = PRIORITIES.includes(f.verdict?.priority) ? f.verdict.priority : 'P3';
      return `<tr class="clickable row-${priority.toLowerCase()}" data-index="${index}">
        <td class="review">${priorityMark(f.verdict?.priority)}</td>
        <td><b class="mono">${esc(intel.cve)}</b></td>
        <td class="num">${intel.cvss_score ?? '<span class="faint">—</span>'}</td>
        <td class="num">${esc(formatEpss(intel) === '미확인' ? '—' : formatEpss(intel))}</td>
        <td class="mono">${fix.fixed_version
          ? esc(fix.fixed_version) : '<span class="none">없음</span>'}</td>
        <td>${evidenceCell(f)}</td>
      </tr>`;
    }).join('')}</tbody></table>`;

  host.querySelectorAll('tr.clickable').forEach((row) => {
    row.addEventListener('click', () => onOpen(findings[Number(row.dataset.index)]));
  });
}

function stepList(items, ordered = false) {
  if (!items?.length) return '';
  const tag = ordered ? 'ol' : 'ul';
  const body = items
    .map((raw) => {
      const [head, ...rest] = String(raw).split('\n');
      const cmd = rest.join('\n').trim();
      return `<li>${esc(head)}${cmd ? `<pre class="step-cmd">${esc(cmd)}</pre>` : ''}</li>`;
    })
    .join('');
  return `<${tag} class="steps">${body}</${tag}>`;
}

/**
 * 상세 패널. 보고서와 같은 절 구조를 따른다.
 *
 * 예전에는 마지막 절에 붉은 점선 상자와 'AI 미전달' 배지를 둘렀다. 걷어냈다 —
 * AI 를 쓰지 않으면 군더더기이고, 쓸 때는 전송 확인 화면에서 무엇이 나가는지
 * 한 번 보여 주는 편이 배지 하나보다 훨씬 확실하다.
 */
export function renderDetail(body, finding, recommendation, narrative) {
  const intel = finding.intel || {};
  const adv = finding.advisory || {};
  const fix = finding.fix || {};
  const inst = finding.installed || {};
  const verdict = finding.verdict || {};
  const det = finding.detection || {};

  const badge = `
    <table class="kv">
      <tr><th>CVSS</th><td>${esc(formatCvss(intel))} <span class="mono faint">${esc(intel.cvss_vector || '')}</span></td></tr>
      <tr><th>EPSS</th><td>${esc(formatEpss(intel))}${
        intel.epss_snapshot_date ? ` <span class="faint">기준일 ${esc(intel.epss_snapshot_date)}</span>` : ''
      }</td></tr>
      <tr><th>CISA KEV</th><td>${esc(formatKev(intel))}</td></tr>
      <tr><th>공개 Exploit</th><td>${esc(formatExploit(intel))}</td></tr>
      <tr><th>수정 버전</th><td class="mono">${esc(adv.fixed_version || '없음')}</td></tr>
      <tr><th>대응 검토</th><td>${priorityPill(verdict.priority)} ←
        ${esc((verdict.fired_rules || []).map((r) => r.name).join(', ') || '기본 등급')}</td></tr>
    </table>`;

  const flags = (verdict.flags || []).length
    ? `<div class="callout"><ul>${verdict.flags
        .map((name) => {
          const f = describeFlag(name);
          return `<li><b>${esc(f.label)}</b>${f.note ? ` — ${esc(f.note)}` : ''}</li>`;
        })
        .join('')}</ul></div>`
    : '';

  const exploitSources = (intel.exploit_sources || []).length
    ? `<p class="faint">Exploit 출처</p><ul class="steps">${intel.exploit_sources
        .map(
          (s) =>
            `<li>${esc(EXPLOIT_SOURCE_LABEL[s.source] || s.source)}: <code>${esc(s.ref)}</code>${
              s.note ? ` — ${esc(s.note)}` : ''
            }</li>`,
        )
        .join('')}</ul>`
    : '';

  const firedRules = (verdict.fired_rules || []).length
    ? `<p class="faint">판정 근거 (발화 룰)</p><ul class="steps">${verdict.fired_rules
        .map((r) => `<li><code>${esc(r.name)}</code> — ${esc(r.explain)}</li>`)
        .join('')}</ul>`
    : '';

  const references = (intel.references || []).length
    ? `<ul class="steps">${intel.references
        .map((u) => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></li>`)
        .join('')}</ul>`
    : '<p class="muted">등록된 참조가 없습니다.</p>';

  const src = narrative?.source === 'ai' ? 'AI 생성 서술' : '룰 기반 서술';
  const rec = recommendation || {};

  body.innerHTML = `
    ${badge}
    ${flags}

    <div class="section">
      <h3>① 취약점 개요</h3>
      <table class="kv">
        <tr><th>CVE</th><td>${esc(intel.cve)}</td></tr>
        <tr><th>취약 제품</th><td>${esc(adv.advisory_package)} (${esc(adv.advisory_ecosystem || '패키지 유형 미상')})</td></tr>
        <tr><th>취약 버전</th><td class="mono">${esc(adv.affected_version_range || '(범위 미공개)')}</td></tr>
        <tr><th>수정 버전</th><td class="mono">${esc(adv.fixed_version || '(없음)')}</td></tr>
        <tr><th>취약점 유형 (CWE)</th><td>${esc((intel.cwe || []).join(', ') || '미확인')}</td></tr>
        <tr><th>심각도</th><td>${esc(SEVERITY_LABEL[intel.severity] || '미확인')}</td></tr>
        <tr><th>공개일</th><td>${esc(intel.published || '미확인')}</td></tr>
      </table>
      ${intel.description ? `<p class="muted">${esc(intel.description)}</p>` : ''}
    </div>

    <div class="section">
      <h3>② 기술적 위험성 <span class="src-badge">${esc(src)}</span></h3>
      <p>${esc(narrative?.technical_risk || '')}</p>
      ${narrative?.preconditions?.length
        ? `<p class="faint">공격 조건</p>${stepList(narrative.preconditions)}` : ''}
      ${narrative?.impact_types?.length
        ? `<p class="faint">공격 성공 시 영향 유형</p>${stepList(narrative.impact_types)}` : ''}
    </div>

    <div class="section">
      <h3>③ 악용 가능성</h3>
      <p>${esc(narrative?.exploitability_note || '')}</p>
      ${exploitSources}
    </div>

    <div class="section">
      <h3>④ 대응 필요성 분석 <span class="src-badge">${esc(src)}</span></h3>
      <p>${esc(narrative?.response_rationale || '')}</p>
      ${firedRules}
    </div>

    <div class="section">
      <h3>⑤ 권고사항</h3>
      <p><b>${esc(rec.action || '')}</b></p>
      ${rec.precheck?.length ? `<p class="faint">패치 전 확인사항</p>${stepList(rec.precheck)}` : ''}
      ${rec.online_steps?.length ? `<p class="faint">${esc(rec.online_title)}</p>${stepList(rec.online_steps, true)}` : ''}
      ${rec.airgapped_steps?.length
        ? `<p class="faint">${esc(rec.airgapped_title)}</p>${
            rec.airgapped_note ? `<p class="muted">${esc(rec.airgapped_note)}</p>` : ''
          }${stepList(rec.airgapped_steps, true)}`
        : ''}
      ${rec.verification?.length ? `<p class="faint">적용 후 검증</p>${stepList(rec.verification)}` : ''}
      ${rec.mitigations?.length
        ? `<p class="faint">임시 완화 방안 (수정 버전 부재)</p>${stepList(rec.mitigations)}` : ''}
    </div>

    <div class="section">
      <h3>⑥ 근거 및 Reference</h3>
      ${references}
    </div>

    <div class="section">
      <h3>⑦ 이 자산에서</h3>
      <table class="kv">
        <tr><th>설치 패키지</th><td>${esc(inst.name)} (${esc(inst.type || '')})</td></tr>
        <tr><th>현재 설치 버전</th><td class="mono">${esc(inst.version)}</td></tr>
        <tr><th>업데이트 가능</th><td>${esc(TERNARY_LABEL[fix.update_available] || '미확인')}</td></tr>
        <tr><th>수정 상태</th><td>${esc(FIX_STATE_LABEL[fix.fix_state] || '미확인')}</td></tr>
        <tr><th>버전 격차</th><td>${esc(fix.version_gap || '미확인')} <span class="faint">(비교자: ${esc(fix.comparator || '')} · 표시용 참고값)</span></td></tr>
        ${inst.locations?.length ? `<tr><th>발견 위치</th><td class="mono">${esc(inst.locations.join(', '))}</td></tr>` : ''}
        <tr><th>Grype 탐지</th><td class="mono">${esc(det.matcher || '')} / ${esc(det.match_type || '')} / ${esc(det.namespace || '')}</td></tr>
        ${fix.reason ? `<tr><th>판정 사유</th><td>${esc(fix.reason)}</td></tr>` : ''}
      </table>
    </div>`;
}
