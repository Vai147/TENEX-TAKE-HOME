"""Application configuration loaded from environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql://tenex:tenex@db:5432/tenex"

    # Auth
    jwt_secret: str = "dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24

    # Seed user (prototype)
    seed_username: str = "analyst"
    seed_password: str = "password123"

    # File storage
    upload_dir: str = "/data/uploads"
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MB

    # Claude
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-haiku-4-5-20251001"

    # VirusTotal threat-intel enrichment (on-demand, free public tier by default)
    virustotal_api_key: str = ""
    virustotal_api_base: str = "https://www.virustotal.com/api/v3"
    # Free public tier is 4 requests/minute, 500/day — the throttle keeps us under it.
    virustotal_rate_per_min: int = 4
    virustotal_timeout_seconds: float = 15.0
    virustotal_cache_ttl_hours: int = 24
    # Hard cap on network lookups per enrich run, so one huge upload cannot drain the
    # daily quota. Indicators beyond this are left un-enriched, not silently dropped.
    virustotal_max_indicators: int = 40
    # A destination is alerted on when at least this many VT engines call it malicious.
    virustotal_alert_min_malicious: int = 1

    # CORS
    frontend_origin: str = "http://localhost:3000"

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.virustotal_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
