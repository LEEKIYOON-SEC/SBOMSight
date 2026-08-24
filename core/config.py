"""환경변수 기반 설정.

기본값은 **AI를 쓰지 않는 쪽(Mode B)** 이다. AI 사용은 명시적으로 켜야 하는
선택 사항이며, 켜지 않아도 SBOMSight의 핵심 기능은 전부 동작한다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


@dataclass
class Config:
    # --- 경로 ---------------------------------------------------------------
    repo_root: Path = REPO_ROOT
    data_dir: Path = field(default_factory=lambda: Path(_env("SBOMSIGHT_DATA_DIR") or REPO_ROOT / "data"))
    policy_dir: Path = field(default_factory=lambda: REPO_ROOT / "policy")
    rules_dir: Path = field(default_factory=lambda: REPO_ROOT / "rules")
    config_dir: Path = field(default_factory=lambda: REPO_ROOT / "config")

    # --- 외부 도구 ----------------------------------------------------------
    syft_bin: str = field(default_factory=lambda: _env("SYFT_BIN") or "syft")
    grype_bin: str = field(default_factory=lambda: _env("GRYPE_BIN") or "grype")
    tool_timeout_sec: int = field(default_factory=lambda: _env_int("SBOMSIGHT_TOOL_TIMEOUT", 900))

    # --- 위협정보 보강 ------------------------------------------------------
    offline: bool = field(default_factory=lambda: _env_bool("SBOMSIGHT_OFFLINE", False))
    enrich_ttl_hours: int = field(default_factory=lambda: _env_int("SBOMSIGHT_ENRICH_TTL_HOURS", 24))
    epss_csv_url: str = field(
        default_factory=lambda: _env("EPSS_CSV_URL") or "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    )
    kev_json_url: str = field(
        default_factory=lambda: _env("KEV_JSON_URL")
        or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    nvd_api_key: str = field(default_factory=lambda: _env("NVD_API_KEY"))
    # 선택 수집기. 기본은 전부 꺼져 있다.
    #
    # EPSS·KEV 는 Grype 가 판정과 같은 출처에서 함께 준다. 남는 것은
    # "공격코드가 공개되어 있다"는 신호 하나인데, Exploit-DB 는 GPL-2.0
    # (copyleft) 이라 사내 반입·배포 기준 확인이 필요하다. 켜지 않아도
    # 우선순위 판정은 KEV·EPSS·CVSS 로 성립한다.
    collect_exploitdb: bool = field(default_factory=lambda: _env_bool("SBOMSIGHT_COLLECT_EXPLOITDB", False))
    collect_metasploit: bool = field(default_factory=lambda: _env_bool("SBOMSIGHT_COLLECT_METASPLOIT", False))
    # 스냅샷이 이보다 오래되면 stale_snapshot 플래그를 세운다.
    snapshot_stale_days: int = field(default_factory=lambda: _env_int("SBOMSIGHT_SNAPSHOT_STALE_DAYS", 7))

    # --- AI (선택) ----------------------------------------------------------
    # 기본값 False. AI 없이도 리포트가 완결되는 것이 이 제품의 전제다.
    #
    # 키는 **서버 프로세스의 환경변수에서만** 읽는다. 브라우저로 내려보내지
    # 않으며, 방문자에게 키를 입력받지도 않는다. 호출은 전부 서버에서 나간다.
    ai_enabled: bool = field(default_factory=lambda: _env_bool("SBOMSIGHT_AI_ENABLED", False))
    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _env("GEMINI_MODEL") or "gemini-3.5-flash-lite")
    # 폴백을 primary와 같게 두지 않는다. 같으면 폴백이 하는 일이 없고, 쿼터가
    # 소진됐을 때 같은 모델을 한 번 더 두드릴 뿐이다. 비워 두면 폴백 없음.
    gemini_fallback_model: str = field(default_factory=lambda: _env("GEMINI_FALLBACK_MODEL"))
    gemini_timeout_sec: int = field(default_factory=lambda: _env_int("GEMINI_TIMEOUT", 120))
    gemini_max_retries: int = field(default_factory=lambda: _env_int("GEMINI_MAX_RETRIES", 3))
    # 한 번에 서술을 만들 수 있는 항목 수. 서술은 CVE 한 건마다 모델을 한 번
    # 부르므로, 8,154개 패키지를 통째로 고르면 48,923번이 되고 그것은 몇 시간에
    # 토큰 한도를 훨씬 넘는 양이다. 조용히 자르지 않고 여기서 거절한다.
    ai_max_findings: int = field(default_factory=lambda: _env_int("SBOMSIGHT_AI_MAX_FINDINGS", 300))
    # 연계 상승 분석. 갈래(발판/상승)마다 이만큼 고른다 — 둘이면 40건 남짓이고
    # 프롬프트가 12~15K 토큰이라 분당 토큰 한도 안에서 한 번에 끝난다.
    escalation_limit: int = field(
        default_factory=lambda: _env_int("SBOMSIGHT_ESCALATION_LIMIT", 20))
    # 후보를 고르려고 훑는 범위. 48,923건을 전부 파이썬으로 되살리지 않는다 —
    # 우선순위 순으로 앞에서부터 이만큼만 보아도 발판·상승 후보는 충분히 나온다.
    escalation_scan_limit: int = field(
        default_factory=lambda: _env_int("SBOMSIGHT_ESCALATION_SCAN_LIMIT", 4000))

    # --- 서버 ---------------------------------------------------------------
    host: str = field(default_factory=lambda: _env("SBOMSIGHT_HOST") or "127.0.0.1")
    port: int = field(default_factory=lambda: _env_int("SBOMSIGHT_PORT", 8000))
    # 실 서버 한 대의 SBOM이 100MB를 넘는다. 다시 손댈 일이 없도록 넉넉히 둔다.
    # 파일을 통째로 메모리에 올리지 않으므로(core/sbom.py inspect) 이 값이 커도
    # 메모리 사용량은 청크 하나에 머문다.
    max_upload_mb: int = field(default_factory=lambda: _env_int("SBOMSIGHT_MAX_UPLOAD_MB", 10240))
    # 보관 시 gzip 압축. SBOM JSON은 구조가 반복적이라 실측 25배 이상 줄어든다.
    compress_storage: bool = field(default_factory=lambda: _env_bool("SBOMSIGHT_COMPRESS_STORAGE", True))

    # --- 접근 통제 ----------------------------------------------------------
    # 접속을 허용할 IP·CIDR (쉼표 구분). **부트스트랩 값이다** — 웹의
    # `설정 → 접근 IP` 에서 한 번이라도 저장하면 그때부터는 DB 값이 쓰인다.
    # 비어 있으면 IP 제한 없음(로그인은 여전히 필요하다).
    allowed_ips: str = field(default_factory=lambda: _env("SBOMSIGHT_ALLOWED_IPS"))
    session_ttl_hours: int = field(default_factory=lambda: _env_int("SBOMSIGHT_SESSION_TTL_HOURS", 12))
    # 놀고 있는 세션을 끊는 시간(분). 마지막 요청으로부터 잰다 — 쓰고 있는 동안은
    # 요청이 계속 나가므로 밀려나지 않는다. 0 이면 유휴 만료 없음(절대 만료만).
    session_idle_minutes: int = field(
        default_factory=lambda: _env_int("SBOMSIGHT_SESSION_IDLE_MINUTES", 10)
    )

    @property
    def db_path(self) -> Path:
        override = _env("SBOMSIGHT_DB_PATH")
        return Path(override) if override else self.data_dir / "sbomsight.db"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def audit_dir(self) -> Path:
        return self.data_dir / "audit"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    def scan_dir(self, scan_id: str) -> Path:
        """스캔 하나의 산출물 보관처 — Grype 원본을 여기에 둔다."""
        return self.data_dir / "scans" / scan_id

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.upload_dir, self.audit_dir, self.cache_dir):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def optional_sources(self) -> frozenset[str]:
        """켜져 있는 선택 수집기 이름."""
        return frozenset(
            name for name, on in (
                ("exploitdb", self.collect_exploitdb),
                ("metasploit", self.collect_metasploit),
            ) if on
        )

    def ai_ready(self) -> bool:
        """AI를 실제로 호출할 수 있는 상태인지."""
        return self.ai_enabled and bool(self.gemini_api_key)


_config: Config | None = None


def get_config(refresh: bool = False) -> Config:
    global _config
    if _config is None or refresh:
        _config = Config()
    return _config
