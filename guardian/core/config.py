"""Application configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"


@dataclass
class Settings:
    """Central application settings."""

    database_url: str = field(
        default_factory=lambda: os.getenv(
            "GUARDIAN_DB_URL", f"sqlite:///{(DATA_DIR / 'guardian.db').as_posix()}"
        )
    )
    api_key: str = field(default_factory=lambda: os.getenv("GUARDIAN_API_KEY", "changeme-guardian-key"))
    nvd_api_key: str | None = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    nvd_base_url: str = field(
        default_factory=lambda: os.getenv(
            "NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
    )
    debug: bool = field(default_factory=lambda: _env_bool("GUARDIAN_DEBUG", False))
    host: str = field(default_factory=lambda: os.getenv("GUARDIAN_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("GUARDIAN_PORT", "8000")))
    report_dir: Path = field(default_factory=lambda: Path(os.getenv("GUARDIAN_REPORT_DIR", str(DATA_DIR / "reports"))))
    vuln_db_dir: Path = field(default_factory=lambda: DATA_DIR / "vuln_db")
    scan_timeout: int = field(default_factory=lambda: int(os.getenv("GUARDIAN_SCAN_TIMEOUT", "300")))

    def __post_init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.vuln_db_dir.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
