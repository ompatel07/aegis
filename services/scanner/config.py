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
    # Semgrep per-file parallelism (Track 1e). 0 = auto (all cgroup-allotted CPUs).
    semgrep_jobs: int = 0
    trivy_bin: str = "trivy"
    gitleaks_bin: str = "gitleaks"
    # Deep-scan backends. Joern (Apache-2.0) is bundled; codeql is opt-in and
    # only used where the customer has installed the CLI under their own license.
    joern_bin: str = "joern"
    joern_parse_bin: str = "joern-parse"
    codeql_bin: str = "codeql"

    # ── Semgrep ──────────────────────────────────────────────────────────────
    semgrep_base_configs: str = Field(
        default="p/owasp-top-ten,p/r2c-security-audit,p/default,p/secrets,p/supply-chain,p/cwe-top-25"
    )
    # High-precision profile (Track 2d): comma-separated Semgrep rule IDs to drop.
    # Empty by default (max recall). Set SEMGREP_EXCLUDE_RULES to silence the
    # low-confidence "security.audit.*" injection rules for a precision-first scan.
    semgrep_exclude_rules: str = ""
    semgrep_rules_cache: str = "/opt/aegis/cache/semgrep"

    @property
    def semgrep_exclude_rule_list(self) -> list[str]:
        return [r.strip() for r in self.semgrep_exclude_rules.split(",") if r.strip()]
    trivy_cache_dir: str = "/opt/aegis/cache/trivy"

    # ── Subprocess timeouts (seconds) ────────────────────────────────────────
    semgrep_timeout_seconds: int = 600
    trivy_timeout_seconds: int = 600
    gitleaks_timeout_seconds: int = 300
    quality_timeout_seconds: int = 300
    deployment_timeout_seconds: int = 900
    deep_scan_timeout_seconds: int = 1800  # CPG build + dataflow is slow

    # ── Deep scan (Joern / CodeQL) ───────────────────────────────────────────
    # Joern's CPG build is memory-hungry; skip deep scan for very large repos.
    deep_scan_max_repo_mb: int = 500

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
