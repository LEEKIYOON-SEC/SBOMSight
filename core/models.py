"""SBOMSight 데이터 모델.

이 모듈의 존재 이유는 단 하나다: **내부 자산 정보와 공개 advisory 정보를
같은 객체에 담지 않는 것.** 두 종류의 데이터가 한 dict 안에 섞이는 순간
외부 전송 시 유출은 시간 문제가 된다. 그래서 계층을 타입으로 갈라 둔다.

    InstalledPackage  [로컬 전용]  우리 자산에 실제로 설치된 것
    AdvisoryPackage   [공개]      공개 advisory가 지목한 패키지 식별자
    VulnIntel         [공개]      CVE·CVSS·EPSS·KEV·Exploit
    Detection         [로컬 전용]  Grype가 어떻게 탐지했는가
    FixAnalysis       [로컬 전용]  설치 버전 ↔ Fixed Version 비교 판정
    RuleVerdict       [로컬 전용]  대응 검토 우선순위와 발화 룰

`Finding`은 위를 모두 묶은 로컬 객체다. 외부(AI)로 나가는 것은 오직
`VulnFact` 하나이며, 이는 `AdvisoryPackage` + `VulnIntel`에서만 조립된다
(core/vulnfact.py 참고). 로컬 전용 계층은 조립 함수의 시그니처에 아예
들어가지 않는다.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# 열거형 — 값은 전부 소문자 문자열이다. 브라우저 JS 구현과 JSON으로 주고받고
# 파리티 테스트로 대조하므로 양쪽이 같은 리터럴을 써야 한다.
# ---------------------------------------------------------------------------


class StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - 표시용
        return self.value


class Ternary(StrEnum):
    """3값 논리.

    `unknown`을 `false`로 뭉개지 않기 위해 존재한다. 버전 문자열이 비표준이라
    비교할 수 없을 때 "취약하지 않음"이라고 답하는 것은 거짓말이다.
    """

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @classmethod
    def of(cls, value: bool | None) -> "Ternary":
        if value is None:
            return cls.UNKNOWN
        return cls.TRUE if value else cls.FALSE

    def is_true(self) -> bool:
        return self is Ternary.TRUE


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, raw: str | None) -> "Severity":
        if not raw:
            return cls.UNKNOWN
        try:
            return cls(raw.strip().lower())
        except ValueError:
            return cls.UNKNOWN


class FixState(StrEnum):
    """공개 advisory 기준의 수정 상태."""

    FIXED_AVAILABLE = "fixed_available"
    NOT_FIXED = "not_fixed"
    WONT_FIX = "wont_fix"
    UNKNOWN = "unknown"


class ExploitMaturity(StrEnum):
    NONE = "none"
    PUBLIC_POC = "public_poc"
    WEAPONIZED = "weaponized"
    UNKNOWN = "unknown"


class Priority(StrEnum):
    """대응 검토 우선순위.

    '위험도'가 아니다. 내부 위험도 판단은 보안담당자의 몫이며 이 값은
    공개 데이터에 룰을 적용한 결과일 뿐이다.
    """

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class VersionGap(StrEnum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    NONE = "none"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 계층 1 — 로컬 전용
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstalledPackage:
    """[로컬 전용 · AI 절대 미전달] 우리 자산의 SBOM에 실제로 존재하는 패키지.

    `name`/`version`은 **우리 환경의 사실**이다. 공개 advisory가 말하는
    패키지 식별자(`AdvisoryPackage.advisory_package`)와 문자열이 같아 보여도
    의미가 다르며, 이쪽은 어떤 경우에도 외부로 나가지 않는다.
    """

    name: str
    version: str
    type: str = ""              # rpm / deb / npm / python / go-module ...
    purl: str = ""
    cpes: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()   # 파일 경로 — 대표적인 내부 정보
    language: str = ""
    sbom_ref: str = ""                # SBOM 내 component bom-ref


@dataclass(frozen=True)
class Detection:
    """[로컬 전용] Grype가 이 매치를 만들어낸 경위.

    리포트의 [로컬 분석 정보]에 실려 "왜 이 패키지가 걸렸는가"를 사람이
    되짚을 수 있게 한다. search_criteria에는 설치 패키지명·버전이 들어가므로
    이 객체 전체가 내부 정보다.
    """

    matcher: str = ""            # rpm-matcher, javascript-matcher ...
    match_type: str = ""         # exact-direct-match, exact-indirect-match ...
    namespace: str = ""          # rocky:distro:rocky:9, github:language:javascript ...
    search_criteria: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 계층 2 — 공개 데이터
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdvisoryPackage:
    """[공개] 공개 advisory가 취약하다고 지목한 패키지/제품 식별자.

    주의: 이것은 **advisory의 식별자**이지 우리가 설치한 패키지가 아니다.
    `affected_version_range`와 `fixed_version` 역시 advisory가 공표한 값이며
    우리 자산의 설치 버전과는 무관하다.
    """

    advisory_package: str
    advisory_ecosystem: str = ""          # rpm / deb / npm / pypi / golang ...
    affected_version_range: str = ""
    fixed_version: str = ""
    fix_state: FixState = FixState.UNKNOWN
    os_family: str = ""                   # rhel / debian / alpine / "" (OS 무관)


@dataclass(frozen=True)
class ExploitSource:
    """[공개] exploit 존재 판정의 출처.

    출처를 댈 수 없는 exploit 주장은 리포트에 쓰지 않는다. 그래서 판정과
    출처를 한 몸으로 묶는다.
    """

    source: str        # exploit_db / github_poc / metasploit / nuclei ...
    ref: str           # EDB-52128, URL 등
    note: str = ""


@dataclass(frozen=True)
class VulnIntel:
    """[공개] 취약점 자체에 대한 공개 위협정보.

    KEV와 exploit은 **다른 개념**이다. KEV는 CISA가 실제 악용을 확인해 등재한
    것이고, exploit_available은 공개된 exploit/PoC 코드의 존재 여부다. 하나가
    참이라고 다른 하나가 참인 것은 아니므로 별개 필드로 둔다.
    """

    cve: str
    aliases: tuple[str, ...] = ()
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_version: str = ""
    cwe: tuple[str, ...] = ()
    description: str = ""                 # 리포트 표시용. VulnFact에는 넣지 않는다.
    published: str = ""
    references: tuple[str, ...] = ()

    # EPSS — 30일 내 악용 관측 확률. **확률 하나만 쓴다.**
    # 백분위는 두지 않는다. "확률 0.11%인데 상위 12%" 라는 두 숫자가 나란히
    # 있으면 어느 쪽을 봐야 하는지 알 수 없고, 판정 룰도 확률만 본다.
    epss: float | None = None
    epss_snapshot_date: str = ""

    # CISA KEV — 실제 악용 확인
    kev: Ternary = Ternary.UNKNOWN
    kev_date_added: str = ""
    kev_ransomware_use: str = ""
    kev_snapshot_date: str = ""

    # 공개 exploit/PoC — KEV와 독립 신호
    exploit_available: Ternary = Ternary.UNKNOWN
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN
    exploit_sources: tuple[ExploitSource, ...] = ()


# ---------------------------------------------------------------------------
# 계층 3 — 로컬 판정
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixAnalysis:
    """[로컬 전용 · AI 절대 미전달] 설치 버전 ↔ Fixed Version 비교 판정.

    "우리가 취약한가"와 "업데이트가 가능한가"는 우리 환경에 대한 사실이므로
    외부로 나가지 않는다. AI는 advisory의 버전 범위만 알 뿐, 우리가 그 범위
    안에 있는지는 모른다.
    """

    installed_version: str
    fixed_version: str = ""
    comparator: str = "generic"          # rpm / semver / pep440 / deb / generic
    is_vulnerable: Ternary = Ternary.UNKNOWN
    update_available: Ternary = Ternary.UNKNOWN
    fix_state: FixState = FixState.UNKNOWN
    version_gap: VersionGap = VersionGap.UNKNOWN
    reason: str = ""                     # unknown일 때 왜 판단하지 못했는지


@dataclass(frozen=True)
class FiredRule:
    """[로컬] 발화한 룰 하나와 그 근거.

    `explain`은 리포트에 그대로 실린다: "epss_high(0.9134 ≥ 0.5)".
    """

    name: str
    explain: str = ""


@dataclass(frozen=True)
class RuleVerdict:
    """[로컬] Rule Engine의 산출물.

    AI에 전달하지 않는다. AI 호출 이후 병합 단계에서만 결합되며, AI 응답에
    우선순위성 필드가 있어도 무시한다.
    """

    priority: Priority
    fired_rules: tuple[FiredRule, ...] = ()
    flags: tuple[str, ...] = ()
    policy_version: str = ""
    policy_sha256: str = ""


# ---------------------------------------------------------------------------
# 종합
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """[로컬] 한 건의 탐지 결과 전체.

    로컬 계층과 공개 계층을 모두 들고 있으므로 **이 객체 자체는 절대 외부로
    나가지 않는다.** 외부로 나가는 것은 vulnfact.build_vuln_fact()가 만드는
    VulnFact 뿐이다.
    """

    installed: InstalledPackage
    advisory: AdvisoryPackage
    intel: VulnIntel
    detection: Detection = field(default_factory=Detection)
    fix: FixAnalysis | None = None
    verdict: RuleVerdict | None = None

    @property
    def key(self) -> str:
        """중복 제거용 키. 같은 CVE라도 패키지가 다르면 다른 finding이다."""
        return f"{self.intel.cve}|{self.installed.name}|{self.installed.version}|{self.installed.purl}"


@dataclass(frozen=True)
class ScanMetadata:
    """[로컬] 스캔 1회에 대한 메타데이터."""

    scan_id: str
    created_at: str
    sbom_filename: str = ""
    sbom_format: str = ""
    sbom_sha256: str = ""
    component_count: int = 0
    grype_version: str = ""
    grype_db_built: str = ""
    provider: str = "grype"
    source: str = ""                 # SBOM이 기술한 대상 — 내부 정보일 수 있다

    # Grype 결과와 우리가 보여 주는 것 사이의 차이를 숨기지 않기 위한 회계.
    # 이 도구는 Grype 를 신뢰하기로 했으므로, 우리 쪽에서 매치가 사라졌다면
    # 몇 건이 왜 사라졌는지 말할 수 있어야 한다.
    grype_match_count: int = 0       # Grype 가 낸 matches 배열의 길이
    merged_count: int = 0            # 같은 (CVE·패키지·버전)이라 합쳐진 매치 수
    dropped: tuple[dict[str, Any], ...] = ()   # 옮기지 못한 매치와 그 사유

    @property
    def accounted(self) -> bool:
        """Grype 매치가 하나도 새지 않았는가."""
        return self.grype_match_count == 0 or not self.dropped


@dataclass(frozen=True)
class ScanResult:
    """[로컬] 스캔 1회의 결과 전체.

    `enrichment`와 `policy`를 함께 싣는 이유는 리포트가 "어떤 데이터로,
    어떤 기준으로 판정했는지"를 스스로 증명할 수 있어야 하기 때문이다.
    스냅샷 기준일과 정책 해시가 없으면 나중에 그 리포트를 재현할 수 없다.
    """

    metadata: ScanMetadata
    findings: tuple[Finding, ...] = ()
    unindexed_packages: tuple[str, ...] = ()   # 브라우저 엔진에서 인덱스 미수록
    enrichment: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 직렬화
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """dataclass/Enum/tuple 트리를 JSON 직렬화 가능한 형태로 바꾼다.

    dataclasses.asdict()를 쓰지 않는 이유는 Enum을 값으로 풀어주지 않고,
    frozen dataclass의 tuple을 list로 바꿔주지 않기 때문이다.
    """
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return obj
