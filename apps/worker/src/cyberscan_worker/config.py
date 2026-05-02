from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_API_SECRET_KEY = "dev-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = Field(default="dev")

    # Mirrors the backend setting; the worker uses it to decrypt per-asset
    # scanner credentials. Worker and backend MUST share the same value.
    api_secret_key: str = Field(default=DEFAULT_API_SECRET_KEY)

    database_url: str = Field(default="postgresql+psycopg://cyberscan:cyberscan@db:5432/cyberscan")
    celery_broker_url: str = Field(default="redis://queue:6379/0")
    celery_result_backend: str = Field(default="redis://queue:6379/1")

    naabu_rate: int = Field(default=1000)
    naabu_concurrency: int = Field(default=50)
    nuclei_shards: int = Field(default=4)
    scan_timeout_min: int = Field(default=20)

    # Crawler (katana). Default 3-deep / 500 URLs / 3-min budget keeps a
    # typical scan inside the 15-min SLA. Intrusive scans go deeper.
    crawl_depth: int = Field(default=3)
    crawl_depth_intrusive: int = Field(default=5)
    crawl_max_urls: int = Field(default=500)
    crawl_timeout_s: int = Field(default=180)

    nvd_api_key: str = Field(default="")
    feeds_use_fixtures: bool = Field(default=True)

    # Notifications
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_from: str = Field(default="cyberscan@example.com")
    smtp_starttls: bool = Field(default=True)

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if self.env.lower() != "dev" and self.api_secret_key == DEFAULT_API_SECRET_KEY:
            raise ValueError(
                "API_SECRET_KEY is set to the built-in default; "
                "generate a strong value before running with ENV != 'dev'."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
