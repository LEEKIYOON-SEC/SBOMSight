"""Grype JSON 출력 → SBOMSight canonical 모델.

정규화 과정에서 로컬 정보와 공개 정보를 **갈라 담는다**. Grype의 match 하나는
아래처럼 쪼개진다:

    match.artifact          → InstalledPackage  [로컬 전용]
    match.matchDetails      → Detection         [로컬 전용]
    match.vulnerability     → AdvisoryPackage + VulnIntel  [공개]

이 분리가 이후 모든 이그레스 안전성의 토대다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import (
    AdvisoryPackage,
    Detection,
    Finding,
    FixState,
    InstalledPackage,
    ScanMetadata,
    ScanResult,
    Severity,
    VulnIntel,
)
from . import fixanalysis

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Grype는 제약식 끝에 형식 이름을 붙여 준다: "< 5.6.2 (rpm)"
_CONSTRAINT_SUFFIX_RE = re.compile(r"\s*\((?:[a-z0-9\-]+)\)\s*$", re.IGNORECASE)

# CVSS 버전 선호도 — 높은 쪽을 대표값으로 삼는다.
_CVSS_RANK = {"4.0": 40, "3.1": 31, "3.0": 30, "2.0": 20}

_FIX_STATE_MAP = {
    "fixed": FixState.FIXED_AVAILABLE,
    "not-fixed": FixState.NOT_FIXED,
    "wont-fix": FixState.WONT_FIX,
    "unknown": FixState.UNKNOWN,
}


# ---------------------------------------------------------------------------
# 보조 파서
# ---------------------------------------------------------------------------


def _clean_constraint(raw: str) -> str:
    """제약식에서 Grype가 붙인 형식 접미사를 떼고 의미를 보존해 옮긴다.

    Grype는 "제약 없음"을 문자열 "none"으로 표현한다. 이는 **모든 버전이
    영향 범위**라는 뜻인데, 그대로 두면 "none"이라는 이름의 버전과 비교하는
    사고가 난다. 그래서 여기서 "*"로 옮겨 둔다.
    """
    cleaned = _CONSTRAINT_SUFFIX_RE.sub("", raw or "").strip()
    if cleaned.lower() in ("none", "all"):
        return "*"
    return cleaned


def _best_cvss(entries: Iterable[dict[str, Any]]) -> tuple[float | None, str, str]:
    """CVSS 항목들 중 대표값 하나를 고른다.

    선호 순서: 버전이 높은 것 → Primary 타입 → 먼저 나온 것.
    """
    best = None
    best_rank = (-1, -1)
    for entry in entries or ():
        if not isinstance(entry, dict):
            continue
        version = str(entry.get("version") or "")
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore")
        if score is None:
            continue
        rank = (
            _CVSS_RANK.get(version, 0),
            1 if str(entry.get("type") or "").lower() == "primary" else 0,
        )
        if rank > best_rank:
            best_rank = rank
            best = (float(score), str(entry.get("vector") or ""), version)
    return best if best else (None, "", "")


def _os_family(distro: dict[str, Any] | None) -> str:
    if not distro:
        return ""
    id_like = distro.get("idLike") or []
    if isinstance(id_like, list) and id_like:
        return str(id_like[0]).lower()
    return str(distro.get("name") or "").lower()


def _rpm_full_version(artifact: dict[str, Any]) -> str:
    """rpm 패키지의 설치 버전에 epoch를 붙여 완전한 EVR로 만든다.

    Grype는 artifact.version에 epoch를 빼고 담으면서 제약식에는
    "< 0:4.18.0-513.el8" 처럼 epoch를 붙여 준다. 그대로 비교하면 epoch 유무가
    갈려 오판이 난다. metadata.epoch가 있으면 앞에 붙여 맞춰 준다.
    """
    version = str(artifact.get("version") or "")
    if artifact.get("type") != "rpm" or ":" in version:
        return version
    metadata = artifact.get("metadata")
    if not isinstance(metadata, dict):
        return version
    epoch = metadata.get("epoch")
    if epoch in (None, "", 0, "0"):
        return version
    return f"{epoch}:{version}"


def _installed_from_artifact(artifact: dict[str, Any]) -> InstalledPackage:
    locations = tuple(
        str(loc.get("path"))
        for loc in artifact.get("locations") or ()
        if isinstance(loc, dict) and loc.get("path")
    )
    return InstalledPackage(
        name=str(artifact.get("name") or ""),
        version=_rpm_full_version(artifact),
        type=str(artifact.get("type") or ""),
        purl=str(artifact.get("purl") or ""),
        cpes=tuple(str(c) for c in artifact.get("cpes") or ()),
        locations=locations,
        language=str(artifact.get("language") or ""),
        sbom_ref=str(artifact.get("id") or ""),
    )


def _detection_from_match(match: dict[str, Any]) -> tuple[Detection, str]:
    """matchDetails에서 탐지 경위와 영향 버전범위를 뽑는다.

    matchDetails는 여러 개일 수 있다(직접 매치 + 상위 패키지 경유 매치 등).
    첫 항목을 대표로 삼되, 버전 제약은 먼저 나오는 유효한 것을 쓴다.
    """
    matcher = ""
    match_type = ""
    namespace = ""
    searched: dict[str, Any] = {}
    constraint = ""

    for detail in match.get("matchDetails") or ():
        if not isinstance(detail, dict):
            continue
        matcher = matcher or str(detail.get("matcher") or "")
        match_type = match_type or str(detail.get("type") or "")

        searched_by = detail.get("searchedBy")
        if isinstance(searched_by, dict):
            if not searched:
                searched = searched_by
            namespace = namespace or str(searched_by.get("namespace") or "")

        found = detail.get("found")
        if isinstance(found, dict) and not constraint:
            constraint = _clean_constraint(str(found.get("versionConstraint") or ""))

    return (
        Detection(matcher=matcher, match_type=match_type, namespace=namespace, search_criteria=searched),
        constraint,
    )


def _merge_vuln_sources(match: dict[str, Any]) -> tuple[str, tuple[str, ...], dict[str, Any]]:
    """대표 CVE ID, 별칭, 병합된 취약점 정보를 고른다.

    Grype의 primary vulnerability는 배포판 advisory(RHSA-…, GHSA-…, ELSA-…)일 때가
    많다. 그 경우 relatedVulnerabilities에 실제 CVE가 들어 있으므로 그쪽을
    대표로 올리고 원래 ID는 별칭으로 남긴다. CVSS·설명·참조는 양쪽을 합친다.
    """
    primary = match.get("vulnerability") or {}
    related = [r for r in (match.get("relatedVulnerabilities") or ()) if isinstance(r, dict)]

    primary_id = str(primary.get("id") or "")
    cve_id = primary_id if _CVE_RE.match(primary_id) else ""
    if not cve_id:
        for rel in related:
            rid = str(rel.get("id") or "")
            if _CVE_RE.match(rid):
                cve_id = rid
                break
    cve_id = cve_id or primary_id

    aliases = tuple(
        dict.fromkeys(
            [primary_id]
            + [str(r.get("id") or "") for r in related]
        )
    )
    aliases = tuple(a for a in aliases if a and a != cve_id)

    # CVSS는 primary 우선, 없으면 related에서 가져온다.
    cvss_entries = list(primary.get("cvss") or ())
    for rel in related:
        cvss_entries.extend(rel.get("cvss") or ())

    description = str(primary.get("description") or "")
    if not description:
        for rel in related:
            if rel.get("description"):
                description = str(rel["description"])
                break

    urls: list[str] = []
    for source in [primary, *related]:
        if source.get("dataSource"):
            urls.append(str(source["dataSource"]))
        urls.extend(str(u) for u in source.get("urls") or ())
    for advisory in primary.get("advisories") or ():
        if isinstance(advisory, dict) and advisory.get("link"):
            urls.append(str(advisory["link"]))

    merged = {
        "cvss": cvss_entries,
        "description": description,
        "urls": tuple(dict.fromkeys(u for u in urls if u)),
        "severity": primary.get("severity") or next((r.get("severity") for r in related if r.get("severity")), ""),
    }
    return cve_id, aliases, merged


# ---------------------------------------------------------------------------
# 공개 진입점
# ---------------------------------------------------------------------------


def normalize_match(match: dict[str, Any], *, os_family: str = "") -> Finding | None:
    """Grype match 하나를 Finding으로 옮긴다."""
    artifact = match.get("artifact")
    vulnerability = match.get("vulnerability")
    if not isinstance(artifact, dict) or not isinstance(vulnerability, dict):
        return None

    installed = _installed_from_artifact(artifact)
    if not installed.name:
        return None

    detection, constraint = _detection_from_match(match)
    cve_id, aliases, merged = _merge_vuln_sources(match)

    fix = vulnerability.get("fix") or {}
    fixed_versions = [str(v) for v in (fix.get("versions") or ()) if v]
    fix_state = _FIX_STATE_MAP.get(str(fix.get("state") or "").lower(), FixState.UNKNOWN)

    advisory = AdvisoryPackage(
        # advisory가 지목한 패키지 식별자. 설치 패키지명과 문자열이 같아 보여도
        # 개념이 다르다 — 이쪽은 공개 데이터다.
        advisory_package=installed.name,
        advisory_ecosystem=installed.type,
        affected_version_range=constraint,
        fixed_version=fixed_versions[0] if fixed_versions else "",
        fix_state=fix_state,
        os_family=os_family,
    )

    score, vector, cvss_version = _best_cvss(merged["cvss"])
    intel = VulnIntel(
        cve=cve_id,
        aliases=aliases,
        severity=Severity.parse(merged["severity"]),
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=cvss_version,
        description=merged["description"],
        references=merged["urls"],
    )

    finding = Finding(installed=installed, advisory=advisory, intel=intel, detection=detection)
    return Finding(
        installed=finding.installed,
        advisory=finding.advisory,
        intel=finding.intel,
        detection=finding.detection,
        fix=fixanalysis.analyze(installed, advisory, detected_by_scanner=True),
    )


def normalize_grype_report(
    payload: dict[str, Any],
    *,
    scan_id: str,
    sbom_filename: str = "",
    sbom_sha256: str = "",
    sbom_format: str = "",
    component_count: int = 0,
) -> ScanResult:
    """Grype JSON 리포트 전체를 ScanResult로 옮긴다."""
    distro = payload.get("distro") if isinstance(payload.get("distro"), dict) else None
    os_family = _os_family(distro)

    descriptor = payload.get("descriptor") or {}
    db = descriptor.get("db") or {} if isinstance(descriptor, dict) else {}

    source = payload.get("source") or {}
    source_desc = ""
    if isinstance(source, dict):
        target = source.get("target")
        if isinstance(target, dict):
            source_desc = str(target.get("userInput") or target.get("path") or "")
        elif isinstance(target, str):
            source_desc = target
        source_desc = source_desc or str(source.get("type") or "")

    # Grype 매치를 하나도 조용히 잃지 않는다. 옮기지 못했거나 합쳐진 것은
    # 개수와 사유를 남겨 화면과 보고서에서 설명할 수 있게 한다. 이 도구는
    # Grype 를 신뢰하기로 했고, 그 신뢰는 "우리가 흘린 게 없다"가 받쳐 준다.
    matches = [m for m in (payload.get("matches") or ()) if isinstance(m, dict)]
    findings: list[Finding] = []
    dropped: list[dict[str, Any]] = []
    seen: set[str] = set()
    merged = 0

    for index, match in enumerate(matches):
        finding = normalize_match(match, os_family=os_family)
        if finding is None:
            vuln = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
            artifact = match.get("artifact") if isinstance(match.get("artifact"), dict) else {}
            dropped.append({
                "index": index,
                "vulnerability": str(vuln.get("id") or ""),
                "package": str(artifact.get("name") or ""),
                "reason": "매치에 패키지 이름이 없어 옮길 수 없었습니다",
            })
            continue
        if finding.key in seen:
            # 같은 취약점·패키지·버전을 Grype 가 여러 경로(cpe/rpm 매처 등)로
            # 찾아낸 경우다. 같은 사실이므로 합치되, 몇 건이었는지는 남긴다.
            merged += 1
            continue
        seen.add(finding.key)
        findings.append(finding)

    metadata = ScanMetadata(
        scan_id=scan_id,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sbom_filename=sbom_filename,
        sbom_format=sbom_format,
        sbom_sha256=sbom_sha256,
        component_count=component_count,
        grype_version=str(descriptor.get("version") or "") if isinstance(descriptor, dict) else "",
        grype_db_built=str(db.get("built") or "") if isinstance(db, dict) else "",
        provider="grype",
        source=source_desc,
        grype_match_count=len(matches),
        merged_count=merged,
        dropped=tuple(dropped),
    )
    return ScanResult(metadata=metadata, findings=tuple(findings))
