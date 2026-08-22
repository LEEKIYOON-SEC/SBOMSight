/** 공용 DOM 렌더링 헬퍼. */

import {
  EXPLOIT_SOURCE_LABEL, FIX_STATE_LABEL, MATURITY_LABEL, PRIORITIES,
  PRIORITY_LABEL, SEVERITY_LABEL, TERNARY_LABEL, UNKNOWN_FLAGS,
  describeFlag, formatCvss, formatEpss, formatExploit, formatKev,
} from './model.js';

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

export function priorityPill(priority) {
  const p = PRIORITIES.includes(priority) ? priority : 'P3';
  return `<span class="pill ${p.toLowerCase()}">${p} ${esc(PRIORITY_LABEL[p])}</span>`;
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
        <div class="k">${p} ${esc(PRIORITY_LABEL[p])}</div>
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
    <span>KEV 등재 <b>${summary.kev_listed}</b>건</span>
    <span class="arrow">·</span>
    <span>공개 Exploit <b>${summary.exploit_available}</b>건</span>`;
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
    tbody.innerHTML = `<tr><td colspan="9" class="muted" style="text-align:center;padding:2rem">
      조건에 맞는 항목이 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = findings
    .map((f, index) => {
      const intel = f.intel || {};
      const fix = f.fix || {};
      const flags = f.verdict?.flags || [];
      const unknownFlags = flags.filter((x) => UNKNOWN_FLAGS.has(x));
      const k = key(f);
      const checked = selected.has(k) ? 'checked' : '';
      return `
      <tr class="clickable" data-index="${index}">
        <td class="pick"><input type="checkbox" data-key="${esc(k)}" ${checked}
          ${selectable ? '' : 'disabled'} aria-label="보고서 대상으로 선택"></td>
        <td>${priorityPill(f.verdict?.priority)}</td>
        <td><b>${esc(intel.cve)}</b>${
          intel.aliases?.length ? `<div class="faint">${esc(intel.aliases.join(', '))}</div>` : ''
        }</td>
        <td>${esc(f.installed?.name)}<div class="faint mono">${esc(f.installed?.type || '')}</div></td>
        <td class="mono">${esc(fix.installed_version || '')}</td>
        <td class="mono">${esc(fix.fixed_version || '—')}</td>
        <td class="num">${intel.cvss_score ?? '—'}</td>
        <td class="num">${intel.epss === null || intel.epss === undefined ? '—' : intel.epss.toFixed(4)}</td>
        <td>
          ${intel.kev === 'true' ? '<span class="tag danger">KEV</span>' : ''}
          ${intel.exploit_available === 'true' ? '<span class="tag warn">Exploit</span>' : ''}
          ${flags.includes('no_fix_available') ? '<span class="tag danger">수정본 없음</span>' : ''}
          ${unknownFlags.length ? `<span class="tag warn">미확인 ${unknownFlags.length}</span>` : ''}
        </td>
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
 * 상세 패널. 리포트와 같은 6절 구조를 따르고, [로컬 분석 정보]는
 * 시각적으로 분리해 'AI 미전달' 배지를 붙인다.
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
      <tr><th>Fixed Version</th><td class="mono">${esc(adv.fixed_version || '없음')}</td></tr>
      <tr><th>판정</th><td>${priorityPill(verdict.priority)} ←
        ${esc((verdict.fired_rules || []).map((r) => r.name).join(', ') || '기본 등급')}</td></tr>
      <tr><th>적용 정책</th><td class="mono faint">v${esc(verdict.policy_version || '')}
        (sha256:${esc((verdict.policy_sha256 || '').slice(0, 12))})</td></tr>
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
        <tr><th>취약 제품</th><td>${esc(adv.advisory_package)} (${esc(adv.advisory_ecosystem || '생태계 미상')})</td></tr>
        <tr><th>취약 버전 (advisory)</th><td class="mono">${esc(adv.affected_version_range || '(범위 미공개)')}</td></tr>
        <tr><th>Fixed Version</th><td class="mono">${esc(adv.fixed_version || '(없음)')}</td></tr>
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

    <div class="section local-box">
      <h3>[로컬 분석 정보] <span class="nosend">AI 미전달</span></h3>
      <p class="muted">아래 정보는 우리 자산에 대한 사실이며 외부(AI)로 전달되지 않습니다.</p>
      <table class="kv">
        <tr><th>설치 패키지</th><td>${esc(inst.name)} (${esc(inst.type || '')})</td></tr>
        <tr><th>현재 설치 버전</th><td class="mono">${esc(inst.version)}</td></tr>
        <tr><th>업데이트 가능</th><td>${esc(TERNARY_LABEL[fix.update_available] || '미확인')}</td></tr>
        <tr><th>수정 상태</th><td>${esc(FIX_STATE_LABEL[fix.fix_state] || '미확인')}</td></tr>
        <tr><th>버전 격차</th><td>${esc(fix.version_gap || '미확인')} <span class="faint">(비교자: ${esc(fix.comparator || '')})</span></td></tr>
        ${inst.locations?.length ? `<tr><th>발견 위치</th><td class="mono">${esc(inst.locations.join(', '))}</td></tr>` : ''}
        <tr><th>Grype 탐지</th><td class="mono">${esc(det.matcher || '')} / ${esc(det.match_type || '')} / ${esc(det.namespace || '')}</td></tr>
        ${fix.reason ? `<tr><th>판정 사유</th><td>${esc(fix.reason)}</td></tr>` : ''}
      </table>
    </div>`;
}
