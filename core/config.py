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

    # --- 서버 ---------------------------------------------------------------
    host: str = field(default_factory=lambda: _env("SBOMSIGHT_HOST") or "127.0.0.1")
    port: int = field(default_factory=lambda: _env_int("SBOMSIGHT_PORT", 8000))
    max_upload_mb: int = field(default_factory=lambda: _env_int("SBOMSIGHT_MAX_UPLOAD_MB", 64))

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

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.upload_dir, self.audit_dir, self.cache_dir):
            path.mkdir(parents=True, exist_ok=True)

    def ai_ready(self) -> bool:
        """AI를 실제로 호출할 수 있는 상태인지."""
        return self.ai_enabled and bool(self.gemini_api_key)


_config: Config | None = None


def get_config(refresh: bool = False) -> Config:
    global _config
    if _config is None or refresh:
        _config = Config()
    return _config
