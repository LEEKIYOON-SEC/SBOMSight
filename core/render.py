"""보고서 렌더링 — Markdown / 인쇄용 HTML.

[로컬 분석 정보]는 시각적으로 분리하고 `AI 미전달` 배지를 붙인다. 보고서를
읽는 사람이 "이 부분은 외부로 나가지 않았다"를 한눈에 알 수 있어야 한다.

AI가 쓴 문장과 룰이 만든 문장도 구분해 표시한다. 독자가 무엇을 읽고 있는지
모르는 채로 판단하게 두지 않기 위한 것이다.
"""

from __future__ import annotations

import html
from typing import Any

from .report import Report, FindingReport

_PRIORITY_STYLE = {
    "P0": ("#b3261e", "#fce8e6"),
    "P1": ("#b35309", "#fdf0e3"),
    "P2": ("#1a5fb4", "#e8f0fe"),
    "P3": ("#4a5568", "#eef1f5"),
}

_SOURCE_LABEL = {"rule": "룰 기반 서술", "ai": "AI 생성 서술"}


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_steps(title: str, steps: list[str] | tuple[str, ...], *, numbered: bool = True) -> list[str]:
    if not steps:
        return []
    lines = [f"**{title}**", ""]
    for idx, step in enumerate(steps, 1):
        head, *rest = str(step).split("\n")
        marker = f"{idx}. " if numbered else "- "
        lines.append(f"{marker}{head}")
        for extra in rest:
            lines.append(f"   {extra}" if extra.strip() else "")
    lines.append("")
    return lines


def _md_finding(item: FindingReport, index: int) -> list[str]:
    o = item.overview
    lines: list[str] = []

    alias = f" (별칭: {', '.join(item.aliases)})" if item.aliases else ""
    lines += [
        f"## {index}. {item.cve} — {item.priority.value} {item.priority_label}{alias}",
        "",
        "| 근거 | 값 |",
        "|---|---|",
        f"| CVSS | {item.badge.cvss} |",
        f"| EPSS | {item.badge.epss} |",
        f"| CISA KEV | {item.badge.kev} |",
        f"| 공개 Exploit | {item.badge.exploit} |",
        f"| Fixed Version | {item.badge.fixed_version} |",
        f"| 판정 | {item.badge.verdict} |",
        f"| 적용 정책 | {item.badge.policy} |",
        "",
    ]

    if item.flags:
        # 인용문은 빈 줄로 끊기면 두 덩어리로 갈라진다. '>' 만 있는 줄로 잇는다.
        lines += ["> **참고 사항**", ">"]
        lines += [f"> - {f['label']}: {f['note']}" for f in item.flags]
        lines += [""]

    # ① 취약점 개요
    cwe_text = ", ".join(o["cwe"]) if o["cwe"] else "미확인"
    score_text = o["cvss_score"] if o["cvss_score"] is not None else "미확인"
    vector_text = f" (`{o['cvss_vector']}`)" if o["cvss_vector"] else ""
    lines += [
        "### ① 취약점 개요",
        "",
        f"- **CVE**: {o['cve']}",
        f"- **취약 제품**: {o['advisory_package']} ({o['advisory_ecosystem'] or '생태계 미상'})",
        f"- **취약 버전 (advisory 기준)**: `{o['affected_version_range']}`",
        f"- **Fixed Version**: `{o['fixed_version']}`",
        f"- **취약점 유형 (CWE)**: {cwe_text}",
        f"- **CVSS**: {score_text}{vector_text}",
        f"- **공개일**: {o['published'] or '미확인'}",
        "",
    ]
    if o["description"]:
        lines += [f"> {o['description']}", ""]

    # ② 기술적 위험성
    t = item.technical_risk
    lines += ["### ② 기술적 위험성", "", t["narrative"], ""]
    if t["preconditions"]:
        lines += ["**공격 조건**", ""] + [f"- {p}" for p in t["preconditions"]] + [""]
    if t["impact_types"]:
        lines += ["**공격 성공 시 영향 유형**", ""] + [f"- {i}" for i in t["impact_types"]] + [""]

    # ③ 악용 가능성
    e = item.exploitability
    if e["epss"] is not None:
        epss_text = f"{e['epss']:.4f}"
        if e["epss_snapshot_date"]:
            epss_text += f" (기준일 {e['epss_snapshot_date']})"
    else:
        epss_text = "미확인"
    lines += [
        "### ③ 악용 가능성",
        "",
        e["narrative"],
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| EPSS | {epss_text} |",
        f"| CISA KEV | {item.badge.kev} |",
        f"| 공개 Exploit | {e['exploit_maturity_label']} |",
        f"| 공개일 | {e['published'] or '미확인'} |",
        "",
    ]
    if e["exploit_sources"]:
        lines += ["**Exploit 출처**", ""]
        lines += [
            f"- {s['label']}: `{s['ref']}`" + (f" — {s['note']}" if s["note"] else "")
            for s in e["exploit_sources"]
        ]
        lines += [""]

    # ④ 대응 필요성 분석
    r = item.response_rationale
    lines += ["### ④ 대응 필요성 분석", "", r["narrative"], ""]
    if r["fired_rules"]:
        lines += ["**판정 근거 (발화 룰)**", ""]
        lines += [f"- `{fr['name']}` — {fr['explain']}" for fr in r["fired_rules"]]
        lines += [""]
    lines += [
        f"**권고 대응 우선순위**: {r['priority']} {r['priority_label']}"
        + (f" — {r['priority_description']}" if r["priority_description"] else ""),
        "",
    ]

    # ⑤ 권고사항
    rec = item.recommendation
    lines += ["### ⑤ 권고사항", "", f"**권고 조치**: {rec.action}", ""]
    lines += _md_steps("패치 전 확인사항", rec.precheck, numbered=False)
    if rec.online_steps:
        lines += _md_steps(rec.online_title, rec.online_steps)
    if rec.airgapped_steps:
        if rec.airgapped_note:
            lines += [f"**{rec.airgapped_title}**", "", f"> {rec.airgapped_note}", ""]
            lines += _md_steps("절차", rec.airgapped_steps)
        else:
            lines += _md_steps(rec.airgapped_title, rec.airgapped_steps)
    if rec.verification:
        lines += _md_steps("적용 후 검증", rec.verification, numbered=False)
    if rec.mitigations:
        lines += _md_steps("임시 완화 방안 (수정 버전 부재)", rec.mitigations, numbered=False)

    # ⑥ 근거 및 Reference
    lines += ["### ⑥ 근거 및 Reference", ""]
    for ref in item.references:
        if ref.get("url"):
            lines.append(f"- {ref['source']}: [{ref['title']}]({ref['url']})")
        else:
            lines.append(f"- {ref['source']}: {ref['title']}")
    lines += [""]

    # [로컬 분석 정보]
    local = item.local_analysis
    fa = local["fix_analysis"]
    lines += [
        "### [로컬 분석 정보] · AI 미전달",
        "",
        "> 아래 정보는 우리 자산에 대한 사실이며 외부(AI)로 전달되지 않았다.",
        "",
        f"- **설치 패키지**: {local['installed_package']} ({local['package_type']})",
        f"- **현재 설치 버전**: `{local['installed_version']}`",
        f"- **Fixed Version**: `{fa['fixed_version'] or '없음'}`",
        f"- **취약 여부**: {fa['is_vulnerable']} · **업데이트 가능**: {fa['update_available']}"
        f" · **수정 상태**: {fa['fix_state']} · **버전 격차**: {fa['version_gap']}"
        f" (비교자: {fa['comparator']})",
        f"- **SBOM 내 발견**: {'예' if local['found_in_sbom'] else '아니오'}",
        f"- **Grype 탐지**: {local['detection']['matcher']} / {local['detection']['match_type']}"
        f" / {local['detection']['namespace']}",
    ]
    if local["locations"]:
        lines.append(f"- **발견 위치**: {', '.join(local['locations'])}")
    if fa["reason"]:
        lines.append(f"- **판정 사유**: {fa['reason']}")
    lines += ["", "---", ""]
    return lines


def to_markdown(report: Report) -> str:
    summary = report.summary
    labels = summary["priority_labels"]

    lines: list[str] = [
        "# 취약점 대응 검토 보고서",
        "",
        f"- 생성 시각: {report.generated_at}",
        f"- 스캔 ID: {report.scan.get('scan_id', '')}",
        f"- 대상 SBOM: {report.scan.get('sbom_filename', '') or '(미상)'}"
        f" ({report.scan.get('sbom_format', '')})",
        f"- 컴포넌트: {report.scan.get('component_count', 0)}개",
        f"- 적용 정책: {report.policy.get('label', '')}",
        f"- 서술 생성: {'AI 사용' if report.ai_used else 'AI 미사용 (룰 기반)'}",
        "",
        "> " + report.disclaimer.replace("\n", "\n> "),
        "",
        "## 요약",
        "",
        "| 대응 검토 우선순위 | 건수 |",
        "|---|---|",
    ]
    for key in ("P0", "P1", "P2", "P3"):
        lines.append(f"| {key} {labels[key]} | {summary['by_priority'][key]} |")
    lines += [
        f"| **합계** | **{summary['total']}** |",
        "",
        f"- 영향 패키지: {summary['affected_packages']}개",
        f"- 취약 확인: {summary['vulnerable_confirmed']}건 · "
        f"판단 불가: {summary['vulnerable_unconfirmed']}건",
        f"- 업데이트 가능: {summary['update_available']}건 · "
        f"수정 버전 없음: {summary['no_fix_available']}건",
        f"- CISA KEV 등재: {summary['kev_listed']}건 · "
        f"공개 Exploit 확인: {summary['exploit_available']}건",
        "",
    ]

    if report.enrichment:
        lines += ["### 사용한 위협정보 스냅샷", "", "| 소스 | 상태 | 수록 | 해당 | 기준일 |", "|---|---|---|---|---|"]
        for name, status in report.enrichment.items():
            lines.append(
                f"| {name} | {status.get('state', '')} | {status.get('entries', 0)} | "
                f"{status.get('matched', 0)} | {status.get('snapshot_date', '') or '-'} |"
            )
        lines.append("")

    lines += ["---", ""]
    for idx, item in enumerate(report.findings, 1):
        lines += _md_finding(item, idx)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 인쇄용 HTML
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _html_list(items, *, ordered: bool = False) -> str:
    if not items:
        return ""
    tag = "ol" if ordered else "ul"
    body = "".join(f"<li><pre class='step'>{_esc(i)}</pre></li>" for i in items)
    return f"<{tag} class='steps'>{body}</{tag}>"


def _html_finding(item: FindingReport, index: int) -> str:
    o, t, e, r = item.overview, item.technical_risk, item.exploitability, item.response_rationale
    rec, local = item.recommendation, item.local_analysis
    fa = local["fix_analysis"]
    color, background = _PRIORITY_STYLE.get(item.priority.value, ("#4a5568", "#eef1f5"))

    flags = ""
    if item.flags:
        rows = "".join(f"<li><b>{_esc(f['label'])}</b> — {_esc(f['note'])}</li>" for f in item.flags)
        flags = f"<div class='callout'><ul>{rows}</ul></div>"

    exploit_sources = ""
    if e["exploit_sources"]:
        rows = "".join(
            f"<li>{_esc(s['label'])}: <code>{_esc(s['ref'])}</code>"
            + (f" — {_esc(s['note'])}" if s["note"] else "")
            + "</li>"
            for s in e["exploit_sources"]
        )
        exploit_sources = f"<p class='label'>Exploit 출처</p><ul>{rows}</ul>"

    fired = ""
    if r["fired_rules"]:
        rows = "".join(
            f"<li><code>{_esc(fr['name'])}</code> — {_esc(fr['explain'])}</li>" for fr in r["fired_rules"]
        )
        fired = f"<p class='label'>판정 근거 (발화 룰)</p><ul>{rows}</ul>"

    references = "".join(
        (
            f"<li>{_esc(ref['source'])}: <a href='{_esc(ref['url'])}'>{_esc(ref['title'])}</a></li>"
            if ref.get("url")
            else f"<li>{_esc(ref['source'])}: {_esc(ref['title'])}</li>"
        )
        for ref in item.references
    )

    airgapped = ""
    if rec.airgapped_steps:
        note = f"<p class='note'>{_esc(rec.airgapped_note)}</p>" if rec.airgapped_note else ""
        airgapped = (
            f"<p class='label'>{_esc(rec.airgapped_title)}</p>{note}"
            f"{_html_list(rec.airgapped_steps, ordered=True)}"
        )

    return f"""
<section class="finding" id="{_esc(item.cve)}">
  <h2><span class="pill" style="color:{color};background:{background}">
      {_esc(item.priority.value)} {_esc(item.priority_label)}</span>
      {index}. {_esc(item.cve)}
      {f"<small>별칭: {_esc(', '.join(item.aliases))}</small>" if item.aliases else ""}</h2>

  <table class="badge">
    <tr><th>CVSS</th><td>{_esc(item.badge.cvss)}</td></tr>
    <tr><th>EPSS</th><td>{_esc(item.badge.epss)}</td></tr>
    <tr><th>CISA KEV</th><td>{_esc(item.badge.kev)}</td></tr>
    <tr><th>공개 Exploit</th><td>{_esc(item.badge.exploit)}</td></tr>
    <tr><th>Fixed Version</th><td>{_esc(item.badge.fixed_version)}</td></tr>
    <tr><th>판정</th><td>{_esc(item.badge.verdict)}</td></tr>
    <tr><th>적용 정책</th><td class="mono">{_esc(item.badge.policy)}</td></tr>
  </table>
  {flags}

  <h3>① 취약점 개요</h3>
  <table class="kv">
    <tr><th>CVE</th><td>{_esc(o['cve'])}</td></tr>
    <tr><th>취약 제품</th><td>{_esc(o['advisory_package'])} ({_esc(o['advisory_ecosystem'] or '생태계 미상')})</td></tr>
    <tr><th>취약 버전 (advisory)</th><td class="mono">{_esc(o['affected_version_range'])}</td></tr>
    <tr><th>Fixed Version</th><td class="mono">{_esc(o['fixed_version'])}</td></tr>
    <tr><th>취약점 유형 (CWE)</th><td>{_esc(', '.join(o['cwe']) if o['cwe'] else '미확인')}</td></tr>
    <tr><th>CVSS</th><td>{_esc(o['cvss_score'] if o['cvss_score'] is not None else '미확인')}
        <span class="mono">{_esc(o['cvss_vector'])}</span></td></tr>
    <tr><th>공개일</th><td>{_esc(o['published'] or '미확인')}</td></tr>
  </table>
  {f"<blockquote>{_esc(o['description'])}</blockquote>" if o['description'] else ""}

  <h3>② 기술적 위험성 <span class="src">{_SOURCE_LABEL.get(item.narrative_source, '')}</span></h3>
  <p>{_esc(t['narrative'])}</p>
  {"<p class='label'>공격 조건</p>" + _html_list(t['preconditions']) if t['preconditions'] else ""}
  {"<p class='label'>공격 성공 시 영향 유형</p>" + _html_list(t['impact_types']) if t['impact_types'] else ""}

  <h3>③ 악용 가능성</h3>
  <p>{_esc(e['narrative'])}</p>
  {exploit_sources}

  <h3>④ 대응 필요성 분석 <span class="src">{_SOURCE_LABEL.get(item.narrative_source, '')}</span></h3>
  <p>{_esc(r['narrative'])}</p>
  {fired}
  <p class="verdict">권고 대응 우선순위: <b>{_esc(r['priority'])} {_esc(r['priority_label'])}</b>
     {f"— {_esc(r['priority_description'])}" if r['priority_description'] else ""}</p>

  <h3>⑤ 권고사항</h3>
  <p class="action">권고 조치: <b>{_esc(rec.action)}</b></p>
  {"<p class='label'>패치 전 확인사항</p>" + _html_list(rec.precheck) if rec.precheck else ""}
  {f"<p class='label'>{_esc(rec.online_title)}</p>" + _html_list(rec.online_steps, ordered=True) if rec.online_steps else ""}
  {airgapped}
  {"<p class='label'>적용 후 검증</p>" + _html_list(rec.verification) if rec.verification else ""}
  {"<p class='label'>임시 완화 방안 (수정 버전 부재)</p>" + _html_list(rec.mitigations) if rec.mitigations else ""}

  <h3>⑥ 근거 및 Reference</h3>
  <ul>{references}</ul>

  <div class="local">
    <h3>[로컬 분석 정보] <span class="nosend">AI 미전달</span></h3>
    <p class="note">아래 정보는 우리 자산에 대한 사실이며 외부(AI)로 전달되지 않았다.</p>
    <table class="kv">
      <tr><th>설치 패키지</th><td>{_esc(local['installed_package'])} ({_esc(local['package_type'])})</td></tr>
      <tr><th>현재 설치 버전</th><td class="mono">{_esc(local['installed_version'])}</td></tr>
      <tr><th>Fixed Version</th><td class="mono">{_esc(fa['fixed_version'] or '없음')}</td></tr>
      <tr><th>취약 여부</th><td>{_esc(fa['is_vulnerable'])}</td></tr>
      <tr><th>업데이트 가능</th><td>{_esc(fa['update_available'])}</td></tr>
      <tr><th>수정 상태 · 버전 격차</th><td>{_esc(fa['fix_state'])} · {_esc(fa['version_gap'])}
          <span class="mono">(비교자: {_esc(fa['comparator'])})</span></td></tr>
      <tr><th>SBOM 내 발견</th><td>{'예' if local['found_in_sbom'] else '아니오'}</td></tr>
      <tr><th>Grype 탐지</th><td class="mono">{_esc(local['detection']['matcher'])} /
          {_esc(local['detection']['match_type'])} / {_esc(local['detection']['namespace'])}</td></tr>
      {f"<tr><th>발견 위치</th><td class='mono'>{_esc(', '.join(local['locations']))}</td></tr>" if local['locations'] else ""}
      {f"<tr><th>판정 사유</th><td>{_esc(fa['reason'])}</td></tr>" if fa['reason'] else ""}
    </table>
  </div>
</section>
"""


_CSS = """
:root{--fg:#1a1d21;--muted:#5a6472;--line:#dde2e8;--bg:#fff;--accent:#1a5fb4;--code:#f4f6f8}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
  "Noto Sans KR","Malgun Gothic",sans-serif;color:var(--fg);background:var(--bg);line-height:1.65}
.wrap{max-width:60rem;margin:0 auto}
h1{font-size:1.7rem;margin:0 0 .5rem;letter-spacing:-.02em}
h2{font-size:1.2rem;margin:2.5rem 0 .75rem;padding-top:1.25rem;border-top:2px solid var(--line)}
h3{font-size:1rem;margin:1.5rem 0 .5rem;color:var(--accent)}
small{font-weight:400;color:var(--muted);font-size:.8rem}
p{margin:.5rem 0}
code,.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}
pre.step{margin:0;white-space:pre-wrap;word-break:break-word;font-family:inherit;font-size:inherit}
ul.steps li,ol.steps li{margin:.35rem 0}
ol.steps li pre.step,ul.steps li pre.step{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:.82rem;background:var(--code);padding:.5rem .65rem;border-radius:4px;border:1px solid var(--line)}
table{border-collapse:collapse;width:100%;margin:.75rem 0;font-size:.9rem}
th,td{border:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:#f7f9fb;font-weight:600;white-space:nowrap;width:11rem}
table.badge th{width:9rem}
.pill{display:inline-block;padding:.15rem .55rem;border-radius:999px;font-size:.78rem;
  font-weight:700;margin-right:.5rem;vertical-align:middle}
.src{font-size:.7rem;font-weight:400;color:var(--muted);border:1px solid var(--line);
  border-radius:3px;padding:.05rem .35rem;margin-left:.4rem;vertical-align:middle}
.nosend{font-size:.7rem;font-weight:700;color:#b3261e;background:#fce8e6;border-radius:3px;
  padding:.1rem .4rem;margin-left:.4rem;vertical-align:middle}
.label{font-weight:600;margin:.9rem 0 .3rem;font-size:.9rem}
.note{color:var(--muted);font-size:.85rem;margin:.25rem 0 .5rem}
.callout{background:#fffbe6;border:1px solid #f0e0a0;border-radius:5px;padding:.5rem .75rem;margin:.75rem 0}
.callout ul{margin:.25rem 0;padding-left:1.1rem;font-size:.87rem}
blockquote{margin:.75rem 0;padding:.5rem .9rem;border-left:3px solid var(--line);
  color:var(--muted);font-size:.9rem}
.local{margin-top:1.5rem;padding:1rem;border:2px dashed #b3261e;border-radius:6px;background:#fffafa}
.local h3{color:#b3261e;margin-top:0}
.verdict,.action{background:var(--code);padding:.5rem .75rem;border-radius:4px}
.summary-disclaimer{background:#f7f9fb;border:1px solid var(--line);border-radius:6px;
  padding:.9rem 1.1rem;margin:1.25rem 0;font-size:.88rem;color:var(--muted)}
.meta{font-size:.87rem;color:var(--muted)}
.meta b{color:var(--fg)}
@media print{
  body{padding:0;font-size:10.5pt}
  h2{page-break-before:auto;break-inside:avoid}
  section.finding{break-inside:avoid-page}
  a{color:inherit;text-decoration:none}
}
"""


def to_html(report: Report) -> str:
    summary = report.summary
    labels = summary["priority_labels"]
    scan = report.scan

    rows = "".join(
        f"<tr><th>{key} {_esc(labels[key])}</th><td>{summary['by_priority'][key]}건</td></tr>"
        for key in ("P0", "P1", "P2", "P3")
    )

    enrichment = ""
    if report.enrichment:
        body = "".join(
            f"<tr><td>{_esc(name)}</td><td>{_esc(s.get('state',''))}</td>"
            f"<td>{s.get('entries',0)}</td><td>{s.get('matched',0)}</td>"
            f"<td>{_esc(s.get('snapshot_date','') or '-')}</td></tr>"
            for name, s in report.enrichment.items()
        )
        enrichment = (
            "<h3>사용한 위협정보 스냅샷</h3>"
            "<table><tr><th>소스</th><th>상태</th><th>수록</th><th>해당</th><th>기준일</th></tr>"
            f"{body}</table>"
        )

    findings = "".join(_html_finding(item, i) for i, item in enumerate(report.findings, 1))

    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>취약점 대응 검토 보고서 — {_esc(scan.get('scan_id',''))}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<h1>취약점 대응 검토 보고서</h1>
<p class="meta">
  생성 <b>{_esc(report.generated_at)}</b> ·
  스캔 <b>{_esc(scan.get('scan_id',''))}</b> ·
  SBOM <b>{_esc(scan.get('sbom_filename','') or '(미상)')}</b> ({_esc(scan.get('sbom_format',''))}) ·
  컴포넌트 <b>{scan.get('component_count',0)}</b>개<br>
  적용 정책 <b>{_esc(report.policy.get('label',''))}</b> ·
  서술 생성 <b>{'AI 사용' if report.ai_used else 'AI 미사용 (룰 기반)'}</b>
</p>
<div class="summary-disclaimer">{_esc(report.disclaimer)}</div>

<h2 style="border-top:none;padding-top:0">요약</h2>
<table>{rows}<tr><th>합계</th><td><b>{summary['total']}건</b></td></tr></table>
<table class="kv">
  <tr><th>영향 패키지</th><td>{summary['affected_packages']}개</td></tr>
  <tr><th>취약 확인 / 판단 불가</th><td>{summary['vulnerable_confirmed']}건 / {summary['vulnerable_unconfirmed']}건</td></tr>
  <tr><th>업데이트 가능 / 수정 버전 없음</th><td>{summary['update_available']}건 / {summary['no_fix_available']}건</td></tr>
  <tr><th>CISA KEV 등재</th><td>{summary['kev_listed']}건</td></tr>
  <tr><th>공개 Exploit 확인</th><td>{summary['exploit_available']}건</td></tr>
</table>
{enrichment}
{findings}
</div></body></html>
"""
