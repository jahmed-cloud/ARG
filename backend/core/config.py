"""
Azure Resource Guardian - Core Configuration
=============================================
Environment-based settings using Pydantic Settings.

All secrets must come from environment variables — never hardcoded.
Uses a layered approach: defaults → .env file → environment variables.
"""

from functools import lru_cache
from typing import List, Optional
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, SecretStr, field_validator
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
    # Used to build the reset link sent to the user and the Microsoft sign-in redirect. Should be the
    # externally-reachable URL of the frontend, e.g. https://arg.yourcompany.com (validated below).
    FRONTEND_BASE_URL: str = "http://localhost:3000"
    # Development only: without SMTP, write password reset links to the backend log. Off by default - anyone
    # who can read the logs could otherwise reset any password. Admins can always reset a user's password.
    LOG_PASSWORD_RESET_LINKS: bool = False

    # -------------------------------------------------------------------------
    # SMTP (optional) — if unset, password reset emails are not sent (and
    # never logged); an admin resets passwords under Settings - Users.
    # Configure these in .env / docker-compose to enable real email delivery.
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
    # JSON arrays of security-group object IDs in AZURE_OAUTH_TENANT_ID. Members of an admin group get the
    # ARG admin role, members of a contributor group the analyst role (scans and findings, not tenants or
    # users); everyone else sees only the subscriptions they own in Azure or were given reader access to.
    ENTRA_ADMIN_GROUP_IDS: list[str] = Field(default_factory=list)
    ENTRA_CONTRIBUTOR_GROUP_IDS: list[str] = Field(default_factory=list)
    # Anyone in AZURE_OAUTH_TENANT_ID may sign in; without a group they are scoped to their subscriptions.
    # Needs AZURE_OAUTH_TENANT_ID set to a tenant GUID (not "common"). False = an admin creates accounts first.
    ENTRA_AUTO_PROVISION: bool = True
    # How long an Azure Owner lease lasts before it is re-checked (at the next token refresh).
    ENTRA_ACCESS_TTL_MINUTES: int = Field(default=30, ge=5, le=60)
    # Group membership is read at Microsoft sign-in; Entra-managed sessions end after this and sign in again.
    ENTRA_SESSION_HOURS: int = Field(default=12, ge=1, le=168)

    @property
    def microsoft_oauth_configured(self) -> bool:
        return bool(self.AZURE_OAUTH_CLIENT_ID and self.AZURE_OAUTH_CLIENT_SECRET)

    @property
    def entra_tenant_bound(self) -> bool:
        """True when sign-in is restricted to one tenant GUID - required for scoped and auto-provisioned users."""
        try:
            UUID(self.AZURE_OAUTH_TENANT_ID)
            return True
        except (TypeError, ValueError):
            return False

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
    # Automatic full scan of every active subscription (cron: minute hour day month weekday), read in
    # SCAN_SCHEDULE_TIMEZONE. Default: every day at 09:00 India Standard Time. FEATURE_SCHEDULED_SCANS=false
    # switches it off; on-demand scans (admins and contributors) are unaffected.
    FULL_SCAN_SCHEDULE: str = "0 9 * * *"
    SCAN_SCHEDULE_TIMEZONE: str = "Asia/Kolkata"
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
    # Refresh the admin Estate inventory (Resource Graph, usage metrics, cost; about 5 minutes) after every
    # completed scan. The Estate page's "Refresh inventory" button works either way.
    ESTATE_REFRESH_AFTER_SCAN: bool = True
    # Write the 5-part subscription analysis (README, current findings, gap analysis, cost drivers, critique,
    # deep dives) after each subscription of a scan - the Analysis page. Adds the cost / inventory collection
    # (about 1-3 minutes per subscription); the scanners are not run twice.
    ANALYSIS_REPORT_AFTER_SCAN: bool = True
    ANALYSIS_REPORTS_KEEP: int = 5   # newest reports kept per subscription

    # -------------------------------------------------------------------------
    # Webhooks (notifications)
    # -------------------------------------------------------------------------
    WEBHOOK_SLACK_URL: Optional[str] = None
    WEBHOOK_TEAMS_URL: Optional[str] = None
    WEBHOOK_CUSTOM_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[SecretStr] = None
    # Webhooks go to public HTTPS endpoints only. true also allows hosts that resolve to private / loopback /
    # link-local addresses (an internal receiver on purpose); cloud metadata stays blocked either way.
    WEBHOOK_ALLOW_PRIVATE_HOSTS: bool = False

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

    @field_validator("FRONTEND_BASE_URL")
    @classmethod
    def validate_frontend_base_url(cls, v: str) -> str:
        """Reset links and the Microsoft sign-in redirect (which carries tokens) are built from it."""
        parsed = urlsplit(v.strip())
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise ValueError("FRONTEND_BASE_URL must be http(s)://host[:port][/path] without credentials, "
                             "query or fragment, e.g. https://arg.example.com")
        return v.strip()


DEFAULT_ADMIN_PASSWORDS = {"changeme", "changeme-before-first-login"}
MIN_ADMIN_PASSWORD_LENGTH = 12
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def production_config_errors(s: Settings) -> List[str]:
    """Settings that must never reach production: placeholder keys and a default or short admin password."""
    errors = []
    if "CHANGE-ME" in s.SECRET_KEY.get_secret_value():
        errors.append("SECRET_KEY is the placeholder - generate one (python -m scripts.configure_env)")
    if "CHANGE-ME" in s.ENCRYPTION_KEY.get_secret_value():
        errors.append("ENCRYPTION_KEY is the placeholder - generate one (python -m scripts.configure_env)")
    admin_password = s.ADMIN_PASSWORD.get_secret_value()
    if admin_password in DEFAULT_ADMIN_PASSWORDS or len(admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
        errors.append(f"ADMIN_PASSWORD is a default or shorter than {MIN_ADMIN_PASSWORD_LENGTH} characters "
                      "(python -m scripts.configure_env --rotate-admin)")
    return errors


def config_warnings(s: Settings) -> List[str]:
    """Risky but legal settings, logged at startup."""
    warnings = []
    frontend = urlsplit(s.FRONTEND_BASE_URL)
    if s.APP_ENV == "production" and frontend.scheme != "https" and frontend.hostname not in LOOPBACK_HOSTS:
        warnings.append("FRONTEND_BASE_URL is not https: reset links and Microsoft sign-in tokens would travel "
                        "unencrypted - use the https URL of your reverse proxy")
    if s.LOG_PASSWORD_RESET_LINKS:
        warnings.append("LOG_PASSWORD_RESET_LINKS is on: password reset links are written to this log - "
                        "development only, anyone who can read the log can reset passwords")
    return warnings


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    lru_cache ensures we only parse .env once per process.
    """
    return Settings()


# Convenience singleton
settings = get_settings()
