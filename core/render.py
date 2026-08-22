"""보고서 렌더링 — Markdown / 인쇄용 HTML.

**패키지 단위로 낸다.** CVE 단위는 조치 단위와 어긋난다 — `openssl` 을 한 번
올리면 CVE 5건이 함께 해소되는데, CVE 단위 보고서는 같은 패치 절차를 다섯 번
설명한다. 실무자가 실행하는 것은 "패키지 업데이트" 한 번이다.

3장 구성:

    1장  요약        무엇이 몇 건이고, 그중 패치로 해소되는 것이 몇 건인가
    2장  조치 대상   패키지 · 현재→목표 버전 · 해소 건수 (결재 문서의 본문)
    3장  패키지별 상세  취약점 표 · 조치 절차 · (AI 사용 시) 연계 분석 · 참조

AI 서술이 없어도 완결된다. AI 를 쓰지 않고 뽑은 문서에는 **전송 관련 문구가
한 줄도 없다** — 쓰지 않은 기능에 대한 해명은 군더더기다.
"""

from __future__ import annotations

import html
from typing import Any

from .report import PackageGroup, Report, FindingReport

_PRIORITY_STYLE = {
    "P0": ("#b3261e", "#fce8e6"),
    "P1": ("#b35309", "#fdf0e3"),
    "P2": ("#1a5fb4", "#e8f0fe"),
    "P3": ("#4a5568", "#eef1f5"),
}

_SOURCE_LABEL = {"rule": "룰 기반 서술", "ai": "AI 생성 서술"}

# 항목이 아니라 **스캔 전체**의 성질인 플래그.
#
# "EPSS 데이터를 확보하지 못했습니다"는 이 CVE 의 성질이 아니라 이번 스캔에
# EPSS 스냅샷이 없었다는 뜻이다. 항목마다 네 줄씩 붙이면 187건에 750줄이
# 되는데, 그 750줄이 말하는 것은 문장 하나다. 1장에 한 번만 싣는다.
_SCAN_WIDE_FLAGS = frozenset({
    "unknown_epss", "unknown_exploit", "unknown_kev", "stale_snapshot",
})


def _coverage_notes(report) -> list[dict[str, str]]:
    """이번 스캔에서 확보하지 못한 데이터. 1장에 한 번 싣는다."""
    seen: dict[str, dict[str, str]] = {}
    for item in report.findings:
        for flag in item.flags:
            if flag["name"] in _SCAN_WIDE_FLAGS:
                seen.setdefault(flag["name"], flag)
    return list(seen.values())


def _percent(value: float | None) -> str:
    """EPSS 확률 → `0.11%`. 백분위는 쓰지 않는다."""
    if value is None:
        return "—"
    percent = value * 100
    if 0 < percent < 0.01:
        return "<0.01%"
    return f"{percent:.2f}".rstrip("0").rstrip(".") + "%"


def _evidence(item: FindingReport) -> str:
    """참인 신호만. '미확인'은 신호가 아니라 값이 없다는 뜻이라 적지 않는다."""
    marks = []
    if item.exploitability.get("kev") == "true":
        marks.append("실제 악용")
    if item.exploitability.get("exploit_available") == "true":
        marks.append("공격코드 공개")
    if not item.overview.get("fixed_version", "").strip("()") or \
            item.overview.get("fixed_version") == "(없음)":
        marks.append("수정본 없음")
    return " · ".join(marks) or "—"


def _target_text(group: PackageGroup) -> str:
    return group.target_version or "없음"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_steps(title: str, steps, *, numbered: bool = True) -> list[str]:
    if not steps:
        return []
    lines = [f"**{title}**", ""]
    for idx, step in enumerate(steps, 1):
        head, *rest = str(step).split("\n")
        lines.append(f"{idx}. {head}" if numbered else f"- {head}")
        for extra in rest:
            lines.append(f"   {extra}" if extra.strip() else "")
    lines.append("")
    return lines


def _md_finding(item: FindingReport) -> list[str]:
    """CVE 한 건 — 묶음 안에서 짧게.

    예전에는 항목마다 7절 145줄이었다. 서버 한 대에 187건이면 2만 줄이 넘어
    아무도 끝까지 읽지 않는다. 판단에 필요한 것은 숫자와 한 문단이다.
    나머지(전체 벡터·발화 룰·Grype 탐지 근거)는 화면 상세에 그대로 있다.
    """
    o = item.overview
    score = o["cvss_score"] if o["cvss_score"] is not None else "—"
    severity = o["severity"]
    lines = [
        f"**{item.cve}** — {item.priority_label} · CVSS {score} {severity}"
        f" · 악용 예측 {_percent(item.exploitability.get('epss'))}"
        + (f" · {_evidence(item)}" if _evidence(item) != "—" else ""),
        "",
    ]
    if o["description"]:
        lines += [f"> {o['description']}", ""]
    if item.technical_risk["narrative"]:
        lines += [item.technical_risk["narrative"], ""]
    if item.response_rationale["narrative"]:
        lines += [item.response_rationale["narrative"], ""]
    actionable = [f for f in item.flags if f["name"] not in _SCAN_WIDE_FLAGS]
    if actionable:
        lines += [f"- {f['label']}: {f['note']}" for f in actionable] + [""]
    return lines


def _specific_steps(steps, package: str, target: str) -> list[str]:
    """이 패키지에만 해당하는 절차만 남긴다.

    폐쇄망 반입 절차(서명 검증 · 로컬 저장소 구성 등)는 같은 패키지 유형이면
    글자 하나까지 같다. 패키지 40개짜리 보고서에 그 40줄을 40번 싣는 것은
    문서를 여덟 배로 부풀리면서 아무것도 더 알려 주지 않는다.

    패키지명이나 목표 버전이 들어 있는 줄만 남기고, 나머지는 앞 절을 가리킨다.
    지우는 것이 아니라 **한 번만 싣는** 것이다.
    """
    return [s for s in steps if package in str(s) or (target and target in str(s))]


def _md_group(group: PackageGroup, index: int, *, full_steps: bool, first_of_type: str) -> list[str]:
    head = f"### 3.{index} {group.package}"
    if group.package_type:
        head += f" ({group.package_type})"
    head += f" — 취약점 {group.cve_count}건"

    lines = [
        head,
        "",
        f"- **현재 설치**: `{group.installed_version}`",
        f"- **목표 버전**: `{_target_text(group)}`",
        f"- **대응 검토**: {group.priority_label}",
    ]
    if group.no_fix_count:
        lines.append(
            f"- **수정 버전 없음**: {group.no_fix_count}건 — 완화 방안 검토가 필요합니다"
        )
    lines += [""]

    lines += ["| CVE | 대응 검토 | CVSS | 악용 예측 | 근거 | 수정 버전 |", "|---|---|---|---|---|---|"]
    for item in group.findings:
        o = item.overview
        lines.append(
            f"| {item.cve} | {item.priority_label} "
            f"| {o['cvss_score'] if o['cvss_score'] is not None else '—'} "
            f"| {_percent(item.exploitability.get('epss'))} "
            f"| {_evidence(item)} "
            f"| `{o['fixed_version']}` |"
        )
    lines += [""]

    if group.chained_analysis:
        lines += [
            "**연계 분석**",
            "",
            "> 공개 데이터(CVSS 벡터 · CWE)만으로 세운 기술적 연계 가능성입니다. "
            "우리 환경의 실제 위험도는 노출 경로와 보상 통제를 함께 보아야 합니다.",
            "",
            group.chained_analysis,
            "",
        ]

    if group.recommendation:
        rec = group.recommendation
        lines += ["**조치**", "", rec.action, ""]
        if rec.online_steps:
            lines += _md_steps(rec.online_title, rec.online_steps)

        if full_steps:
            lines += _md_steps("패치 전 확인사항", rec.precheck, numbered=False)
            if rec.airgapped_steps:
                if rec.airgapped_note:
                    lines += [f"**{rec.airgapped_title}**", "", f"> {rec.airgapped_note}", ""]
                    lines += _md_steps("절차", rec.airgapped_steps)
                else:
                    lines += _md_steps(rec.airgapped_title, rec.airgapped_steps)
            if rec.verification:
                lines += _md_steps("적용 후 검증", rec.verification, numbered=False)
        else:
            # 같은 패키지 유형의 공통 절차는 앞 절에 이미 실려 있다.
            specific = _specific_steps(rec.airgapped_steps, group.package, group.target_version)
            lines += [
                f"**{rec.airgapped_title}** — 공통 절차는 `{first_of_type}` 항목을 참고하세요. "
                f"이 패키지에만 해당하는 부분은 다음과 같습니다.",
                "",
            ]
            lines += _md_steps("이 패키지 전용", specific) if specific else []
            if rec.verification:
                lines += _md_steps(
                    "적용 후 검증",
                    _specific_steps(rec.verification, group.package, group.target_version)
                    or rec.verification,
                    numbered=False,
                )
    else:
        # 수정본이 없는 묶음. 완화 방안은 CVE 항목의 playbook 에 들어 있다.
        mitigations = [m for item in group.findings for m in item.recommendation.mitigations]
        lines += _md_steps(
            "임시 완화 방안 (수정 버전 부재)", list(dict.fromkeys(mitigations)), numbered=False
        )

    lines += ["**취약점별 상세**", ""]
    for item in group.findings:
        lines += _md_finding(item)

    references = _merge_references(group)
    if references:
        lines += ["**참조**", ""]
        for ref in references:
            lines.append(
                f"- {ref['source']}: [{ref['title']}]({ref['url']})" if ref.get("url")
                else f"- {ref['source']}: {ref['title']}"
            )
        lines += [""]

    lines += ["---", ""]
    return lines


def _merge_references(group: PackageGroup) -> list[dict[str, str]]:
    """묶음 안의 참조를 URL 기준으로 합친다. 같은 벤더 advisory 가 반복된다."""
    seen: dict[str, dict[str, str]] = {}
    for item in group.findings:
        for ref in item.references:
            key = ref.get("url") or f"{ref.get('source')}:{ref.get('title')}"
            seen.setdefault(key, dict(ref))
    return list(seen.values())


def to_markdown(report: Report) -> str:
    summary = report.summary
    labels = summary["priority_labels"]
    scan = report.scan

    lines: list[str] = [
        "# 취약점 대응 검토 보고서",
        "",
        f"- 생성 시각: {report.generated_at}",
        f"- 스캔 ID: {scan.get('scan_id', '')}",
        f"- 대상 SBOM: {scan.get('sbom_filename', '') or '(미상)'} ({scan.get('sbom_format', '')})",
        f"- 컴포넌트: {scan.get('component_count', 0)}개",
    ]
    # AI 를 쓰지 않았으면 AI 이야기를 꺼내지 않는다.
    if report.ai_used:
        lines.append("- 서술 생성: AI 사용 (공개 취약점 데이터만 전달)")
    lines += ["", f"> {report.disclaimer}", ""]

    # --- 1장 요약 ---------------------------------------------------------
    lines += [
        "## 1. 요약",
        "",
        f"탐지 **{summary['total']}건** · 영향 패키지 **{summary['affected_packages']}개**",
        "",
        "| 대응 검토 | 건수 |",
        "|---|---|",
    ]
    for key in ("P0", "P1", "P2", "P3"):
        lines.append(f"| {labels[key]} | {summary['by_priority'][key]} |")
    lines += [
        "",
        f"- 패치로 해소 가능: **{summary['update_available']}건**",
        f"- 수정 버전 없음: **{summary['no_fix_available']}건** (완화 방안 검토 필요)",
        f"- 실제 악용 확인: {summary['kev_listed']}건 · 공격코드 공개: {summary['exploit_available']}건",
        "",
    ]

    notes = _coverage_notes(report)
    if notes:
        lines += ["**확보하지 못한 데이터**", ""]
        lines += [f"- {n['label']}: {n['note']}" for n in notes]
        lines += [""]

    if report.enrichment:
        lines += [
            "| 위협정보 소스 | 상태 | 수록 | 해당 | 기준일 |",
            "|---|---|---|---|---|",
        ]
        for name, status in report.enrichment.items():
            lines.append(
                f"| {name} | {status.get('state', '')} | {status.get('entries', 0)} | "
                f"{status.get('matched', 0)} | {status.get('snapshot_date', '') or '-'} |"
            )
        lines.append("")

    # --- 2장 조치 대상 ----------------------------------------------------
    fixable = [g for g in report.packages if g.resolvable]
    blocked = [g for g in report.packages if not g.resolvable]

    lines += ["## 2. 조치 대상", ""]
    if fixable:
        lines += [
            f"패키지 **{len(fixable)}개**를 업데이트하면 취약점 "
            f"**{sum(g.fixable_count for g in fixable)}건**이 해소됩니다.",
            "",
            "| 대응 검토 | 패키지 | 현재 → 목표 | 해소 | 취약점 |",
            "|---|---|---|---|---|",
        ]
        for group in fixable:
            lines.append(
                f"| {group.priority_label} | {group.package} "
                f"| `{group.installed_version}` → `{group.target_version}` "
                f"| {group.fixable_count}건 | {', '.join(group.cves)} |"
            )
        lines.append("")
    else:
        lines += ["패치로 해소할 수 있는 항목이 없습니다.", ""]

    if blocked:
        lines += [
            f"### 수정 버전이 없는 패키지 ({len(blocked)}개)",
            "",
            "업데이트로 해소할 수 없습니다. 완화 방안은 3장 각 항목에 있습니다.",
            "",
            "| 대응 검토 | 패키지 | 설치 버전 | 취약점 |",
            "|---|---|---|---|",
        ]
        for group in blocked:
            lines.append(
                f"| {group.priority_label} | {group.package} "
                f"| `{group.installed_version}` | {', '.join(group.cves)} |"
            )
        lines.append("")

    # --- 3장 패키지별 상세 ------------------------------------------------
    lines += ["## 3. 패키지별 상세", ""]
    seen_types: dict[str, str] = {}
    for index, group in enumerate(report.packages, 1):
        kind = group.package_type or "generic"
        first = seen_types.get(kind)
        lines += _md_group(group, index, full_steps=first is None, first_of_type=first or "")
        seen_types.setdefault(kind, group.package)

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


def _html_finding(item: FindingReport) -> str:
    o = item.overview
    score = o["cvss_score"] if o["cvss_score"] is not None else "—"
    description = f"<blockquote>{_esc(o['description'])}</blockquote>" if o["description"] else ""
    narratives = "".join(
        f"<p>{_esc(text)}</p>"
        for text in (item.technical_risk["narrative"], item.response_rationale["narrative"])
        if text
    )
    actionable = [f for f in item.flags if f["name"] not in _SCAN_WIDE_FLAGS]
    flags = ""
    if actionable:
        body = "".join(f"<li><b>{_esc(f['label'])}</b> — {_esc(f['note'])}</li>" for f in actionable)
        flags = f"<div class='callout'><ul>{body}</ul></div>"

    source = _SOURCE_LABEL.get(item.narrative_source, "")
    return f"""
<div class="cve">
  <p class="cve-head"><b>{_esc(item.cve)}</b> — {_esc(item.priority_label)}
    · CVSS {_esc(score)} {_esc(o['severity'])}
    · 악용 예측 {_esc(_percent(item.exploitability.get('epss')))}
    {f"· {_esc(_evidence(item))}" if _evidence(item) != "—" else ""}
    <span class="src">{_esc(source)}</span></p>
  {description}
  {narratives}
  {flags}
</div>"""


def _html_group(group: PackageGroup, index: int, *, full_steps: bool, first_of_type: str) -> str:
    color, background = _PRIORITY_STYLE.get(group.priority.value, ("#4a5568", "#eef1f5"))

    rows = "".join(
        f"<tr><td class='mono'>{_esc(i.cve)}</td><td>{_esc(i.priority_label)}</td>"
        f"<td>{_esc(i.overview['cvss_score'] if i.overview['cvss_score'] is not None else '—')}</td>"
        f"<td>{_esc(_percent(i.exploitability.get('epss')))}</td>"
        f"<td>{_esc(_evidence(i))}</td>"
        f"<td class='mono'>{_esc(i.overview['fixed_version'])}</td></tr>"
        for i in group.findings
    )

    chained = ""
    if group.chained_analysis:
        chained = f"""
<h4>연계 분석</h4>
<blockquote>공개 데이터(CVSS 벡터 · CWE)만으로 세운 기술적 연계 가능성입니다.
우리 환경의 실제 위험도는 노출 경로와 보상 통제를 함께 보아야 합니다.</blockquote>
<p>{_esc(group.chained_analysis)}</p>"""

    if group.recommendation:
        rec = group.recommendation
        steps = f"<h4>조치</h4><p class='action'>{_esc(rec.action)}</p>"
        if rec.online_steps:
            steps += f"<p class='label'>{_esc(rec.online_title)}</p>{_html_list(rec.online_steps, ordered=True)}"

        if full_steps:
            if rec.precheck:
                steps += f"<p class='label'>패치 전 확인사항</p>{_html_list(rec.precheck)}"
            if rec.airgapped_steps:
                note = f"<p class='note'>{_esc(rec.airgapped_note)}</p>" if rec.airgapped_note else ""
                steps += (f"<p class='label'>{_esc(rec.airgapped_title)}</p>{note}"
                          f"{_html_list(rec.airgapped_steps, ordered=True)}")
            if rec.verification:
                steps += f"<p class='label'>적용 후 검증</p>{_html_list(rec.verification)}"
        else:
            specific = _specific_steps(rec.airgapped_steps, group.package, group.target_version)
            steps += (
                f"<p class='label'>{_esc(rec.airgapped_title)}</p>"
                f"<p class='note'>공통 절차는 <b>{_esc(first_of_type)}</b> 항목을 참고하세요. "
                f"이 패키지에만 해당하는 부분은 다음과 같습니다.</p>"
                + _html_list(specific, ordered=True)
            )
            verification = (_specific_steps(rec.verification, group.package, group.target_version)
                            or list(rec.verification))
            if verification:
                steps += f"<p class='label'>적용 후 검증</p>{_html_list(verification)}"
    else:
        mitigations = list(dict.fromkeys(
            m for item in group.findings for m in item.recommendation.mitigations
        ))
        steps = ("<h4>임시 완화 방안 (수정 버전 부재)</h4>" + _html_list(mitigations)
                 if mitigations else "")

    references = _merge_references(group)
    ref_html = ""
    if references:
        body = "".join(
            f"<li>{_esc(r['source'])}: <a href='{_esc(r['url'])}'>{_esc(r['title'])}</a></li>"
            if r.get("url") else f"<li>{_esc(r['source'])}: {_esc(r['title'])}</li>"
            for r in references
        )
        ref_html = f"<h4>참조</h4><ul class='steps'>{body}</ul>"

    no_fix = ""
    if group.no_fix_count:
        no_fix = (f"<tr><th>수정 버전 없음</th><td>{group.no_fix_count}건 — "
                  f"완화 방안 검토가 필요합니다</td></tr>")

    return f"""
<section class="group">
  <h3>3.{index} {_esc(group.package)}
    {f"<small>({_esc(group.package_type)})</small>" if group.package_type else ""}
    <span class="pill" style="color:{color};background:{background}">{_esc(group.priority_label)}</span>
    <small>취약점 {group.cve_count}건</small></h3>
  <table>
    <tr><th>현재 설치</th><td class="mono">{_esc(group.installed_version)}</td></tr>
    <tr><th>목표 버전</th><td class="mono">{_esc(_target_text(group))}</td></tr>
    {no_fix}
  </table>
  <table>
    <tr><th>CVE</th><th>대응 검토</th><th>CVSS</th><th>악용 예측</th><th>근거</th><th>수정 버전</th></tr>
    {rows}
  </table>
  {chained}
  {steps}
  <h4>취약점별 상세</h4>
  {''.join(_html_finding(i) for i in group.findings)}
  {ref_html}
</section>"""


_CSS = """
:root{--fg:#1a1d21;--muted:#5a6472;--line:#dde2e8;--bg:#fff;--accent:#1a5fb4;--code:#f4f6f8}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
  "Noto Sans KR","Malgun Gothic",sans-serif;color:var(--fg);background:var(--bg);line-height:1.65}
.wrap{max-width:60rem;margin:0 auto}
h1{font-size:1.7rem;margin:0 0 .5rem;letter-spacing:-.02em}
h2{font-size:1.25rem;margin:2.5rem 0 .75rem;padding-top:1.25rem;border-top:2px solid var(--line)}
h3{font-size:1.05rem;margin:2rem 0 .5rem;color:var(--accent)}
h4{font-size:.92rem;margin:1.25rem 0 .4rem}
small{font-weight:400;color:var(--muted);font-size:.8rem}
p{margin:.5rem 0}
code,.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}
pre.step{margin:0;white-space:pre-wrap;word-break:break-word;font-family:inherit;font-size:inherit}
ul.steps li,ol.steps li{margin:.35rem 0}
ol.steps li pre.step,ul.steps li pre.step{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:.82rem;background:var(--code);padding:.5rem .65rem;border-radius:4px;border:1px solid var(--line)}
table{border-collapse:collapse;width:100%;margin:.75rem 0;font-size:.9rem}
th,td{border:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:#f7f9fb;font-weight:600;white-space:nowrap}
.pill{display:inline-block;padding:.15rem .55rem;border-radius:999px;font-size:.78rem;
  font-weight:700;margin-left:.5rem;vertical-align:middle}
.src{font-size:.7rem;font-weight:400;color:var(--muted);border:1px solid var(--line);
  border-radius:3px;padding:.05rem .35rem;margin-left:.4rem;vertical-align:middle}
.label{font-weight:600;margin:.9rem 0 .3rem;font-size:.9rem}
.note{color:var(--muted);font-size:.85rem;margin:.25rem 0 .5rem}
.callout{background:#fffbe6;border:1px solid #f0e0a0;border-radius:5px;padding:.5rem .75rem;margin:.5rem 0}
.callout ul{margin:.25rem 0;padding-left:1.1rem;font-size:.87rem}
blockquote{margin:.75rem 0;padding:.5rem .9rem;border-left:3px solid var(--line);
  color:var(--muted);font-size:.9rem}
.cve{margin:.9rem 0;padding-left:.9rem;border-left:2px solid var(--line)}
.cve-head{margin:0 0 .25rem;font-size:.92rem}
.action{background:var(--code);padding:.5rem .75rem;border-radius:4px}
.summary-disclaimer{background:#f7f9fb;border:1px solid var(--line);border-radius:6px;
  padding:.9rem 1.1rem;margin:1.25rem 0;font-size:.88rem;color:var(--muted)}
.meta{font-size:.87rem;color:var(--muted)}
.meta b{color:var(--fg)}
@media print{
  body{padding:0;font-size:10.5pt}
  section.group{break-inside:avoid-page}
  a{color:inherit;text-decoration:none}
}
"""


def to_html(report: Report) -> str:
    summary = report.summary
    labels = summary["priority_labels"]
    scan = report.scan

    priority_rows = "".join(
        f"<tr><th>{_esc(labels[key])}</th><td>{summary['by_priority'][key]}건</td></tr>"
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
            "<table><tr><th>위협정보 소스</th><th>상태</th><th>수록</th><th>해당</th>"
            f"<th>기준일</th></tr>{body}</table>"
        )

    notes = _coverage_notes(report)
    coverage = ""
    if notes:
        body = "".join(f"<li><b>{_esc(n['label'])}</b> — {_esc(n['note'])}</li>" for n in notes)
        coverage = f"<p class='label'>확보하지 못한 데이터</p><div class='callout'><ul>{body}</ul></div>"

    fixable = [g for g in report.packages if g.resolvable]
    blocked = [g for g in report.packages if not g.resolvable]

    if fixable:
        rows = "".join(
            f"<tr><td>{_esc(g.priority_label)}</td><td><b>{_esc(g.package)}</b></td>"
            f"<td class='mono'>{_esc(g.installed_version)} → {_esc(g.target_version)}</td>"
            f"<td>{g.fixable_count}건</td><td class='mono'>{_esc(', '.join(g.cves))}</td></tr>"
            for g in fixable
        )
        action_table = (
            f"<p>패키지 <b>{len(fixable)}개</b>를 업데이트하면 취약점 "
            f"<b>{sum(g.fixable_count for g in fixable)}건</b>이 해소됩니다.</p>"
            "<table><tr><th>대응 검토</th><th>패키지</th><th>현재 → 목표</th>"
            f"<th>해소</th><th>취약점</th></tr>{rows}</table>"
        )
    else:
        action_table = "<p>패치로 해소할 수 있는 항목이 없습니다.</p>"

    blocked_table = ""
    if blocked:
        rows = "".join(
            f"<tr><td>{_esc(g.priority_label)}</td><td><b>{_esc(g.package)}</b></td>"
            f"<td class='mono'>{_esc(g.installed_version)}</td>"
            f"<td class='mono'>{_esc(', '.join(g.cves))}</td></tr>"
            for g in blocked
        )
        blocked_table = (
            f"<h3>수정 버전이 없는 패키지 ({len(blocked)}개)</h3>"
            "<p>업데이트로 해소할 수 없습니다. 완화 방안은 3장 각 항목에 있습니다.</p>"
            "<table><tr><th>대응 검토</th><th>패키지</th><th>설치 버전</th>"
            f"<th>취약점</th></tr>{rows}</table>"
        )

    groups = ""
    seen_types: dict[str, str] = {}
    for index, group in enumerate(report.packages, 1):
        kind = group.package_type or "generic"
        first = seen_types.get(kind)
        groups += _html_group(group, index, full_steps=first is None, first_of_type=first or "")
        seen_types.setdefault(kind, group.package)
    ai_line = (
        "<br>서술 생성 <b>AI 사용</b> (공개 취약점 데이터만 전달)" if report.ai_used else ""
    )

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
  컴포넌트 <b>{scan.get('component_count',0)}</b>개{ai_line}
</p>
<div class="summary-disclaimer">{_esc(report.disclaimer)}</div>

<h2 style="border-top:none;padding-top:0">1. 요약</h2>
<p>탐지 <b>{summary['total']}건</b> · 영향 패키지 <b>{summary['affected_packages']}개</b></p>
<table>{priority_rows}<tr><th>합계</th><td><b>{summary['total']}건</b></td></tr></table>
<table>
  <tr><th>패치로 해소 가능</th><td>{summary['update_available']}건</td></tr>
  <tr><th>수정 버전 없음</th><td>{summary['no_fix_available']}건 (완화 방안 검토 필요)</td></tr>
  <tr><th>실제 악용 확인</th><td>{summary['kev_listed']}건</td></tr>
  <tr><th>공격코드 공개</th><td>{summary['exploit_available']}건</td></tr>
</table>
{coverage}
{enrichment}

<h2>2. 조치 대상</h2>
{action_table}
{blocked_table}

<h2>3. 패키지별 상세</h2>
{groups}
</div></body></html>
"""
