"""Application configuration loaded from the environment.

Uses pydantic-settings so every value is validated and typed at startup. A bad
config fails fast (the process exits) rather than surfacing as a confusing
runtime error mid-scan.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── HTTP server ──────────────────────────────────────────────────────────
    scanner_host: str = "0.0.0.0"
    scanner_port: int = 8000

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    environment: str = "development"

    # ── Tool binaries ────────────────────────────────────────────────────────
    semgrep_bin: str = "semgrep"
    trivy_bin: str = "trivy"
    gitleaks_bin: str = "gitleaks"

    # ── Semgrep ──────────────────────────────────────────────────────────────
    semgrep_base_configs: str = Field(
        default="p/owasp-top-ten,p/r2c-security-audit,p/default,p/secrets,p/supply-chain,p/cwe-top-25"
    )
    semgrep_rules_cache: str = "/opt/aegis/cache/semgrep"
    trivy_cache_dir: str = "/opt/aegis/cache/trivy"

    # ── Subprocess timeouts (seconds) ────────────────────────────────────────
    semgrep_timeout_seconds: int = 600
    trivy_timeout_seconds: int = 600
    gitleaks_timeout_seconds: int = 300
    quality_timeout_seconds: int = 300
    deployment_timeout_seconds: int = 900

    # ── Deployment engine ────────────────────────────────────────────────────
    deployment_build_enabled: bool = True

    @property
    def semgrep_base_config_list(self) -> list[str]:
        """Parse the comma-separated registry string into a clean list."""
        return [c.strip() for c in self.semgrep_base_configs.split(",") if c.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide singleton Settings instance."""
    return Settings()
