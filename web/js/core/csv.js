/**
 * 표 → CSV.
 *
 * 결재와 공유는 결국 엑셀로 돈다. 화면에서 읽은 것을 그대로 옮길 수 없으면
 * 담당자는 표를 다시 손으로 옮겨 적게 된다.
 *
 * **UTF-8 BOM 을 붙인다.** 없으면 Windows 엑셀이 CSV 를 시스템 코드페이지
 * (한국어 Windows 에서는 CP949)로 읽어 한글이 전부 깨진다. `.ps1` 에서 겪은
 * 것과 같은 문제다.
 */

import { PRIORITY_LABEL } from './model.js';
import { formatProbability } from './format.js';

const COLUMNS = [
  ['대응 검토', (f) => PRIORITY_LABEL[f.verdict?.priority] || ''],
  ['CVE', (f) => f.intel?.cve || ''],
  ['패키지', (f) => f.installed?.name || ''],
  ['패키지 유형', (f) => f.installed?.type || ''],
  ['설치 버전', (f) => f.installed?.version || ''],
  ['수정 버전', (f) => f.advisory?.fixed_version || ''],
  ['수정 상태', (f) => f.fix?.fix_state || ''],
  ['CVSS', (f) => (f.intel?.cvss_score ?? '')],
  ['심각도', (f) => f.intel?.severity || ''],
  ['악용 예측', (f) => (f.intel?.epss === null || f.intel?.epss === undefined
    ? '미확인' : formatProbability(f.intel.epss))],
  ['실제 악용(KEV)', (f) => ({ true: '예', false: '아니오' }[f.intel?.kev] || '미확인')],
  ['공격코드 공개', (f) => ({ true: '예', false: '아니오' }[f.intel?.exploit_available] || '미확인')],
  ['CWE', (f) => (f.intel?.cwe || []).join(' ')],
];

/**
 * RFC 4180. 따옴표는 두 번 써서 이스케이프하고, 구분자·따옴표·줄바꿈이 들어 있는
 * 값만 감싼다. 앞에 `=`·`+`·`-`·`@` 가 오는 값은 엑셀이 수식으로 해석하므로
 * 작은따옴표를 앞세운다 — CVE 설명 같은 외부 문자열이 그대로 들어오는 자리다.
 */
function cell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(findings) {
  const rows = [COLUMNS.map(([name]) => cell(name)).join(',')];
  for (const finding of findings) {
    rows.push(COLUMNS.map(([, get]) => cell(get(finding))).join(','));
  }
  return `﻿${rows.join('\r\n')}\r\n`;
}

export function downloadCsv(findings, filename) {
  const blob = new Blob([toCsv(findings)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
