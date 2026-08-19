/**
 * 보고서 Markdown 렌더링 — core/render.py 의 to_markdown() 동형.
 *
 * 데모에서도 담당자가 결재 문서로 가져갈 수 있는 산출물이 나와야 한다.
 * HTML은 report.html 페이지가 이미 렌더링하고 인쇄(PDF)를 제공하므로
 * 여기서는 Markdown만 만든다.
 */

function steps(title, items, { numbered = true } = {}) {
  if (!items?.length) return [];
  const lines = [`**${title}**`, ''];
  items.forEach((step, index) => {
    const [head, ...rest] = String(step).split('\n');
    lines.push(`${numbered ? `${index + 1}. ` : '- '}${head}`);
    for (const extra of rest) lines.push(extra.trim() ? `   ${extra}` : '');
  });
  lines.push('');
  return lines;
}

function renderFinding(item, index) {
  const o = item.overview;
  const t = item.technical_risk;
  const e = item.exploitability;
  const r = item.response_rationale;
  const rec = item.recommendation;
  const local = item.local_analysis;
  const fa = local.fix_analysis;
  const lines = [];

  const alias = item.aliases?.length ? ` (별칭: ${item.aliases.join(', ')})` : '';
  lines.push(
    `## ${index}. ${item.cve} — ${item.priority} ${item.priority_label}${alias}`, '',
    '| 근거 | 값 |', '|---|---|',
    `| CVSS | ${item.badge.cvss} |`,
    `| EPSS | ${item.badge.epss} |`,
    `| CISA KEV | ${item.badge.kev} |`,
    `| 공개 Exploit | ${item.badge.exploit} |`,
    `| Fixed Version | ${item.badge.fixed_version} |`,
    `| 판정 | ${item.badge.verdict} |`,
    `| 적용 정책 | ${item.badge.policy} |`, '',
  );

  if (item.flags?.length) {
    lines.push('> **참고 사항**', '>');
    for (const f of item.flags) lines.push(`> - ${f.label}: ${f.note}`);
    lines.push('');
  }

  const score = o.cvss_score ?? '미확인';
  lines.push(
    '### ① 취약점 개요', '',
    `- **CVE**: ${o.cve}`,
    `- **취약 제품**: ${o.advisory_package} (${o.advisory_ecosystem || '생태계 미상'})`,
    `- **취약 버전 (advisory 기준)**: \`${o.affected_version_range}\``,
    `- **Fixed Version**: \`${o.fixed_version}\``,
    `- **취약점 유형 (CWE)**: ${o.cwe?.length ? o.cwe.join(', ') : '미확인'}`,
    `- **CVSS**: ${score}${o.cvss_vector ? ` (\`${o.cvss_vector}\`)` : ''}`,
    `- **공개일**: ${o.published || '미확인'}`, '',
  );
  if (o.description) lines.push(`> ${o.description}`, '');

  lines.push('### ② 기술적 위험성', '', t.narrative, '');
  if (t.preconditions?.length) lines.push('**공격 조건**', '', ...t.preconditions.map((p) => `- ${p}`), '');
  if (t.impact_types?.length) lines.push('**공격 성공 시 영향 유형**', '', ...t.impact_types.map((i) => `- ${i}`), '');

  const epssText = (e.epss !== null && e.epss !== undefined)
    ? `${e.epss.toFixed(4)}${e.epss_snapshot_date ? ` (기준일 ${e.epss_snapshot_date})` : ''}`
    : '미확인';
  lines.push(
    '### ③ 악용 가능성', '', e.narrative, '',
    '| 항목 | 값 |', '|---|---|',
    `| EPSS | ${epssText} |`,
    `| CISA KEV | ${item.badge.kev} |`,
    `| 공개 Exploit | ${e.exploit_maturity_label} |`,
    `| 공개일 | ${e.published || '미확인'} |`, '',
  );
  if (e.exploit_sources?.length) {
    lines.push('**Exploit 출처**', '');
    for (const s of e.exploit_sources) {
      lines.push(`- ${s.label}: \`${s.ref}\`${s.note ? ` — ${s.note}` : ''}`);
    }
    lines.push('');
  }

  lines.push('### ④ 대응 필요성 분석', '', r.narrative, '');
  if (r.fired_rules?.length) {
    lines.push('**판정 근거 (발화 룰)**', '');
    for (const fr of r.fired_rules) lines.push(`- \`${fr.name}\` — ${fr.explain}`);
    lines.push('');
  }
  lines.push(`**권고 대응 우선순위**: ${r.priority} ${r.priority_label}`
    + (r.priority_description ? ` — ${r.priority_description}` : ''), '');

  lines.push('### ⑤ 권고사항', '', `**권고 조치**: ${rec.action}`, '');
  lines.push(...steps('패치 전 확인사항', rec.precheck, { numbered: false }));
  if (rec.online_steps?.length) lines.push(...steps(rec.online_title, rec.online_steps));
  if (rec.airgapped_steps?.length) {
    if (rec.airgapped_note) {
      lines.push(`**${rec.airgapped_title}**`, '', `> ${rec.airgapped_note}`, '');
      lines.push(...steps('절차', rec.airgapped_steps));
    } else {
      lines.push(...steps(rec.airgapped_title, rec.airgapped_steps));
    }
  }
  if (rec.verification?.length) lines.push(...steps('적용 후 검증', rec.verification, { numbered: false }));
  if (rec.mitigations?.length) {
    lines.push(...steps('임시 완화 방안 (수정 버전 부재)', rec.mitigations, { numbered: false }));
  }

  lines.push('### ⑥ 근거 및 Reference', '');
  for (const ref of item.references || []) {
    lines.push(ref.url ? `- ${ref.source}: [${ref.title}](${ref.url})` : `- ${ref.source}: ${ref.title}`);
  }
  lines.push('');

  lines.push(
    '### [로컬 분석 정보] · AI 미전달', '',
    '> 아래 정보는 우리 자산에 대한 사실이며 외부(AI)로 전달되지 않았다.', '',
    `- **설치 패키지**: ${local.installed_package} (${local.package_type})`,
    `- **현재 설치 버전**: \`${local.installed_version}\``,
    `- **Fixed Version**: \`${fa.fixed_version || '없음'}\``,
    `- **취약 여부**: ${fa.is_vulnerable} · **업데이트 가능**: ${fa.update_available}`
    + ` · **수정 상태**: ${fa.fix_state} · **버전 격차**: ${fa.version_gap} (비교자: ${fa.comparator})`,
    `- **SBOM 내 발견**: ${local.found_in_sbom ? '예' : '아니오'}`,
    `- **Grype 탐지**: ${local.detection.matcher} / ${local.detection.match_type} / ${local.detection.namespace}`,
  );
  if (local.locations?.length) lines.push(`- **발견 위치**: ${local.locations.join(', ')}`);
  if (fa.reason) lines.push(`- **판정 사유**: ${fa.reason}`);
  lines.push('', '---', '');
  return lines;
}

export function renderMarkdown(report) {
  const s = report.summary;
  const labels = s.priority_labels;
  const scan = report.scan || {};

  const lines = [
    '# 취약점 대응 검토 보고서', '',
    `- 생성 시각: ${report.generated_at}`,
    `- 스캔 ID: ${scan.scan_id || ''}`,
    `- 대상 SBOM: ${scan.sbom_filename || '(미상)'} (${scan.sbom_format || ''})`,
    `- 컴포넌트: ${scan.component_count || 0}개`,
    `- 적용 정책: ${report.policy?.label || ''}`,
    `- 서술 생성: ${report.ai_used ? 'AI 사용' : 'AI 미사용 (룰 기반)'}`,
    '',
    `> ${report.disclaimer.replace(/\n/g, '\n> ')}`, '',
    '## 요약', '',
    '| 대응 검토 우선순위 | 건수 |', '|---|---|',
  ];
  for (const key of ['P0', 'P1', 'P2', 'P3']) {
    lines.push(`| ${key} ${labels[key]} | ${s.by_priority[key]} |`);
  }
  lines.push(
    `| **합계** | **${s.total}** |`, '',
    `- 영향 패키지: ${s.affected_packages}개`,
    `- 취약 확인: ${s.vulnerable_confirmed}건 · 판단 불가: ${s.vulnerable_unconfirmed}건`,
    `- 업데이트 가능: ${s.update_available}건 · 수정 버전 없음: ${s.no_fix_available}건`,
    `- CISA KEV 등재: ${s.kev_listed}건 · 공개 Exploit 확인: ${s.exploit_available}건`, '',
  );

  const enrichment = report.enrichment || {};
  if (Object.keys(enrichment).length) {
    lines.push('### 사용한 위협정보 스냅샷', '', '| 소스 | 상태 | 수록 | 해당 | 기준일 |', '|---|---|---|---|---|');
    for (const [name, status] of Object.entries(enrichment)) {
      lines.push(`| ${name} | ${status.state || ''} | ${status.entries || 0} | `
        + `${status.matched || 0} | ${status.snapshot_date || '-'} |`);
    }
    lines.push('');
  }

  lines.push('---', '');
  report.findings.forEach((item, index) => lines.push(...renderFinding(item, index + 1)));
  return lines.join('\n');
}
