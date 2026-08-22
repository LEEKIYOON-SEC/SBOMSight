"""우리가 보여 주는 것이 Grype 가 말한 것과 같은지 대조한다.

이 도구는 **Grype 를 신뢰하기로 선택한 도구**다. Grype 가 틀리면 그것은 Grype 의
오류이고 감수한다. 하지만 우리 코드 때문에 결과가 달라지는 것은 감수 대상이
아니다 — 정규화, 보강, 정렬, 저장 중 어디에서도 매치가 사라지거나 값이 바뀌면
안 된다.

말로 하는 약속은 검증할 수 없으므로 명령으로 만든다.

    grype sbom:sbom.json -o json > grype.json
    python -m core.cli verify grype.json findings.json

대조하는 것:
  1. 매치 개수      Grype 의 matches 를 하나도 잃지 않았는가
  2. 취약점 식별자  Grype 가 말한 ID 가 우리 CVE 나 별칭에 남아 있는가
  3. 패키지·버전    Grype 가 지목한 그 패키지, 그 버전인가
  4. 수정 버전      Grype 의 fix.versions 를 그대로 옮겼는가
  5. 수정 상태      Grype 의 fix.state 를 그대로 옮겼는가

같은 (취약점·패키지·버전)을 Grype 가 여러 매처로 중복 보고하는 것은 합치되,
합친 개수를 회계에 남긴다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult

# Grype 의 fix.state 문자열 → 우리 FixState 값
_STATE_EQUIV = {
    "fixed": "fixed_available",
    "not-fixed": "not_fixed",
    "wont-fix": "wont_fix",
    "unknown": "unknown",
    "": "unknown",
}


@dataclass
class Mismatch:
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.kind}] {self.detail}"


@dataclass
class VerifyReport:
    grype_matches: int = 0
    our_findings: int = 0
    merged: int = 0
    dropped: int = 0
    mismatches: list[Mismatch] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def summary(self) -> str:
        lines = [
            f"Grype 매치      {self.grype_matches}건",
            f"우리 탐지       {self.our_findings}건",
            f"중복 합침       {self.merged}건",
            f"옮기지 못함     {self.dropped}건",
        ]
        if self.grype_matches:
            accounted = self.our_findings + self.merged + self.dropped
            lines.append(
                f"회계            {accounted} / {self.grype_matches}"
                f"{'  일치' if accounted == self.grype_matches else '  ⚠ 어긋남'}"
            )
        lines.append("")
        lines.append("결과            " + ("일치 — Grype 결과가 그대로 보존되었습니다"
                                           if self.ok else f"불일치 {len(self.mismatches)}건"))
        return "\n".join(lines)


def _grype_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Grype 원본에서 대조에 쓸 값만 뽑는다."""
    rows = []
    for match in payload.get("matches") or ():
        if not isinstance(match, dict):
            continue
        artifact = match.get("artifact") or {}
        vuln = match.get("vulnerability") or {}
        if not isinstance(artifact, dict) or not isinstance(vuln, dict):
            continue
        fix = vuln.get("fix") or {}
        rows.append({
            "id": str(vuln.get("id") or ""),
            "package": str(artifact.get("name") or ""),
            "version": str(artifact.get("version") or ""),
            "fixed_versions": sorted(str(v) for v in (fix.get("versions") or ()) if v),
            "state": _STATE_EQUIV.get(str(fix.get("state") or "").lower(), "unknown"),
        })
    return rows


def _our_index(findings: tuple[Finding, ...]) -> dict[tuple[str, str], Finding]:
    """(취약점 식별자, 패키지) → Finding.

    Grype 의 primary 가 RHSA·GHSA 인 경우 우리는 관련 CVE 를 대표로 올리고
    원래 ID 는 별칭에 남긴다. 그래서 별칭까지 색인해야 Grype 가 말한 ID 로
    되찾을 수 있다.
    """
    index: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        package = finding.installed.name
        for identifier in (finding.intel.cve, *finding.intel.aliases):
            if identifier:
                index.setdefault((identifier, package), finding)
    return index


def verify(raw_grype: dict[str, Any], result: ScanResult) -> VerifyReport:
    """Grype 원본과 우리 결과를 대조한다."""
    rows = _grype_rows(raw_grype)
    report = VerifyReport(
        grype_matches=len(rows),
        our_findings=len(result.findings),
        merged=result.metadata.merged_count,
        dropped=len(result.metadata.dropped),
    )
    index = _our_index(result.findings)

    for row in rows:
        finding = index.get((row["id"], row["package"]))
        if finding is None:
            report.mismatches.append(Mismatch(
                "누락",
                f"{row['id']} · {row['package']} — Grype 가 보고했으나 우리 결과에 없습니다",
            ))
            continue

        if finding.installed.version != row["version"]:
            # epoch 복원(`0:1.2.3`)은 의도된 보정이므로 접미 일치를 허용한다.
            if not finding.installed.version.endswith(row["version"]):
                report.mismatches.append(Mismatch(
                    "버전 불일치",
                    f"{row['id']} · {row['package']} — Grype '{row['version']}' "
                    f"vs 우리 '{finding.installed.version}'",
                ))

        ours_fixed = finding.advisory.fixed_version
        if row["fixed_versions"] and ours_fixed not in row["fixed_versions"]:
            report.mismatches.append(Mismatch(
                "수정 버전 불일치",
                f"{row['id']} · {row['package']} — Grype {row['fixed_versions']} "
                f"vs 우리 '{ours_fixed}'",
            ))

        ours_state = finding.advisory.fix_state.value
        if ours_state != row["state"]:
            report.mismatches.append(Mismatch(
                "수정 상태 불일치",
                f"{row['id']} · {row['package']} — Grype '{row['state']}' vs 우리 '{ours_state}'",
            ))

    accounted = report.our_findings + report.merged + report.dropped
    if report.grype_matches and accounted != report.grype_matches:
        report.mismatches.append(Mismatch(
            "회계 불일치",
            f"Grype 매치 {report.grype_matches}건이 "
            f"탐지 {report.our_findings} + 합침 {report.merged} + 미전환 {report.dropped} "
            f"= {accounted} 와 맞지 않습니다",
        ))

    return report


def load_grype_json(path: Path) -> dict[str, Any]:
    """Grype 산출물을 읽는다. gzip 보관본도 그대로 받는다."""
    from . import artifacts

    return json.loads(artifacts.read_bytes(Path(path)).decode("utf-8"))
