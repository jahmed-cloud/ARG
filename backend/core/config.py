"""
Azure Resource Guardian - Core Configuration
=============================================
Environment-based settings using Pydantic Settings.

All secrets must come from environment variables — never hardcoded.
Uses a layered approach: defaults → .env file → environment variables.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "Azure Resource Guardian"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # -------------------------------------------------------------------------
    # API
    # -------------------------------------------------------------------------
    API_PREFIX: str = "/api/v1"
    # Stored as a raw string (not List[str]) because pydantic-settings
    # attempts to JSON-decode any complex-typed field's environment value
    # BEFORE field_validator(mode="before") ever runs — so a plain
    # comma-separated .env value like "http://a,http://b" fails with a
    # SettingsError before our validator gets a chance to split it.
    # Use the `allowed_origins_list` property below to get the parsed list.
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    DOCS_ENABLED: bool = True  # Disable in production if desired

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "postgresql+asyncpg://arg:argpassword@localhost:5432/arg"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False

    # Sync URL for Alembic migrations
    @property
    def DATABASE_URL_SYNC(self) -> str:
        return self.DATABASE_URL.replace("+asyncpg", "")

    # -------------------------------------------------------------------------
    # Redis / Celery
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_RESULT_EXPIRES: int = 86400  # 24 hours

    # -------------------------------------------------------------------------
    # JWT Authentication
    # -------------------------------------------------------------------------
    SECRET_KEY: SecretStr = Field(default="CHANGE-ME-IN-PRODUCTION-USE-OPENSSL-RAND-HEX-32")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------------------------------------------------------
    # Encryption (for Azure credentials stored in DB)
    # -------------------------------------------------------------------------
    ENCRYPTION_KEY: SecretStr = Field(default="CHANGE-ME-32-CHAR-ENCRYPTION-KEY!")

    # -------------------------------------------------------------------------
    # Initial Admin User (created on first startup)
    # -------------------------------------------------------------------------
    ADMIN_EMAIL: str = "admin@local.dev"
    ADMIN_PASSWORD: SecretStr = Field(default="changeme")
    ADMIN_USERNAME: str = "admin"

    # -------------------------------------------------------------------------
    # Password Reset
    # -------------------------------------------------------------------------
    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 30
    # Used to build the reset link sent to the user (or logged, if SMTP is
    # unconfigured). Should be the externally-reachable URL of the frontend,
    # e.g. https://arg.yourcompany.com
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    # -------------------------------------------------------------------------
    # SMTP (optional) — if unset, password reset links are logged server-side
    # instead of emailed, so the feature works out of the box with zero
    # extra setup. Configure these in .env / docker-compose to enable real
    # email delivery.
    # -------------------------------------------------------------------------
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: str | None = None
    SMTP_PASSWORD: SecretStr | None = None
    SMTP_FROM_EMAIL: str = "noreply@arg.local"
    SMTP_USE_TLS: bool = True

    @property
    def smtp_configured(self) -> bool:
        return bool(self.SMTP_HOST and self.SMTP_FROM_EMAIL)

    # -------------------------------------------------------------------------
    # Microsoft OAuth / "Sign in with Microsoft" (optional) — only enabled
    # when both AZURE_OAUTH_CLIENT_ID and AZURE_OAUTH_CLIENT_SECRET are set
    # via environment variables. This is a separate, dedicated app
    # registration from the per-tenant scanning Service Principals
    # configured in Settings — it authenticates ARG *users*, not Azure
    # resource access.
    # -------------------------------------------------------------------------
    AZURE_OAUTH_CLIENT_ID: str | None = None
    AZURE_OAUTH_CLIENT_SECRET: SecretStr | None = None
    # "common" allows any Microsoft work/school/personal account; set to a
    # specific tenant GUID to restrict sign-in to one organization.
    AZURE_OAUTH_TENANT_ID: str = "common"
    AZURE_OAUTH_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/microsoft/callback"

    @property
    def microsoft_oauth_configured(self) -> bool:
        return bool(self.AZURE_OAUTH_CLIENT_ID and self.AZURE_OAUTH_CLIENT_SECRET)

    # -------------------------------------------------------------------------
    # Azure SDK Global Settings
    # -------------------------------------------------------------------------
    AZURE_SDK_TIMEOUT: int = 30
    AZURE_SDK_MAX_RETRIES: int = 3
    AZURE_RESOURCE_GRAPH_BATCH_SIZE: int = 1000
    AZURE_COST_LOOKBACK_DAYS: int = 30

    # -------------------------------------------------------------------------
    # Scanner Settings
    # -------------------------------------------------------------------------
    SCANNER_TIMEOUT_SECONDS: int = 300
    SCANNER_MAX_CONCURRENT: int = 10
    FULL_SCAN_SCHEDULE: str = "0 2 * * *"  # Daily at 02:00 UTC (cron)
    SCAN_RESULT_RETENTION_DAYS: int = 90

    # -------------------------------------------------------------------------
    # Report Settings
    # -------------------------------------------------------------------------
    REPORT_STORAGE_PATH: str = "/tmp/arg/reports"
    REPORT_RETENTION_DAYS: int = 30
    REPORT_MAX_SIZE_MB: int = 100

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    BCRYPT_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    SESSION_COOKIE_SECURE: bool = True
    # Same rationale as ALLOWED_ORIGINS above: stored as a raw comma-separated
    # string, not List[str], to avoid pydantic-settings' premature JSON-decode
    # attempt on complex-typed env vars. Use trusted_proxies_list to get the
    # parsed list. Not currently consumed anywhere — reserved for future
    # reverse-proxy IP allowlisting middleware.
    TRUSTED_PROXIES: str = ""

    # -------------------------------------------------------------------------
    # Feature Flags
    # -------------------------------------------------------------------------
    FEATURE_TERRAFORM_DRIFT: bool = True
    FEATURE_ENTRA_HYGIENE: bool = True
    FEATURE_COST_ANALYSIS: bool = True
    FEATURE_AUTO_REMEDIATION: bool = False  # Disabled by default — safety first
    FEATURE_SCHEDULED_SCANS: bool = True
    FEATURE_WEBHOOKS: bool = True

    # -------------------------------------------------------------------------
    # Webhooks (notifications)
    # -------------------------------------------------------------------------
    WEBHOOK_SLACK_URL: Optional[str] = None
    WEBHOOK_TEAMS_URL: Optional[str] = None
    WEBHOOK_CUSTOM_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[SecretStr] = None

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------
    @property
    def allowed_origins_list(self) -> List[str]:
        """Parsed CORS origins, split from the raw comma-separated ALLOWED_ORIGINS string."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def trusted_proxies_list(self) -> List[str]:
        """Parsed trusted proxy IPs/CIDRs, split from the raw TRUSTED_PROXIES string."""
        return [p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()]

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v):
        if v == "production":
            # Production safety checks are enforced at startup in main.py
            pass
        return v


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    lru_cache ensures we only parse .env once per process.
    """
    return Settings()


# Convenience singleton
settings = get_settings()
