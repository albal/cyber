from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_API_SECRET_KEY = "dev-secret-change-me"
DEFAULT_SEED_ADMIN_PASSWORD = "admin"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # `env` gates startup safety checks. Anything other than "dev" requires
    # api_secret_key to be set to a non-default value (see _validate_secrets).
    env: str = Field(default="dev")

    api_secret_key: str = Field(default=DEFAULT_API_SECRET_KEY)
    database_url: str = Field(default="postgresql+psycopg://cyberscan:cyberscan@db:5432/cyberscan")
    redis_url: str = Field(default="redis://queue:6379/0")
    celery_broker_url: str = Field(default="redis://queue:6379/0")
    celery_result_backend: str = Field(default="redis://queue:6379/1")

    s3_endpoint: str = Field(default="http://minio:9000")
    s3_access_key: str = Field(default="cyberscan")
    s3_secret_key: str = Field(default="cyberscan-secret")
    s3_bucket_artifacts: str = Field(default="cyberscan-artifacts")
    s3_bucket_feeds: str = Field(default="cyberscan-feeds")

    jwt_algorithm: str = Field(default="HS256")
    jwt_expires_min: int = Field(default=60)
    seed_admin_email: str = Field(default="admin@example.com")
    seed_admin_password: str = Field(default="admin")

    # Comma-separated origins, or '*' to allow any (allow_credentials forced false in that case).
    cors_origins: str = Field(default="*")

    # Login rate-limit. 5 attempts / 5min by default. The bucket is keyed
    # by IP + email so a stuffer can't lock out a target from many IPs.
    login_rate_max_attempts: int = Field(default=5)
    login_rate_window_s: int = Field(default=300)

    # OIDC: when oidc_issuer is set, the backend additionally accepts bearer
    # JWTs signed by that issuer (verified via its JWKS). Users are provisioned
    # on first sign-in into the tenant whose slug matches `oidc_default_tenant`.
    oidc_issuer: str = Field(default="")
    oidc_audience: str = Field(default="cyberscan")
    oidc_default_tenant: str = Field(default="default")
    oidc_email_claim: str = Field(default="email")
    oidc_role_claim: str = Field(default="role")

    # Comma-separated CIDRs / IPs of trusted reverse proxies. Only requests
    # whose immediate peer IP is in this list will have X-Forwarded-For
    # honored — otherwise the header is ignored, so a client can't spoof
    # source IP to bypass per-IP rate limits.
    trusted_proxies: str = Field(default="")

    # When False (the default), HTTP fetches initiated by the backend on
    # behalf of users (target verification, asset health probes) refuse to
    # connect to private/loopback/link-local addresses. Self-hosters
    # verifying intranet apps can flip this to True at their own risk.
    allow_private_targets: bool = Field(default=False)

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if self.env.lower() != "dev":
            if self.api_secret_key == DEFAULT_API_SECRET_KEY:
                raise ValueError(
                    "API_SECRET_KEY is set to the built-in default; "
                    "generate a strong value before running with ENV != 'dev'."
                )
            if self.seed_admin_password == DEFAULT_SEED_ADMIN_PASSWORD:
                raise ValueError(
                    "SEED_ADMIN_PASSWORD is set to the built-in default; "
                    "set a real password before running with ENV != 'dev'."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
