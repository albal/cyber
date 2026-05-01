from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql+psycopg://cyberscan:cyberscan@db:5432/cyberscan")
    celery_broker_url: str = Field(default="redis://queue:6379/0")
    celery_result_backend: str = Field(default="redis://queue:6379/1")

    naabu_rate: int = Field(default=1000)
    naabu_concurrency: int = Field(default=50)
    nuclei_shards: int = Field(default=4)
    scan_timeout_min: int = Field(default=20)

    nvd_api_key: str = Field(default="")
    feeds_use_fixtures: bool = Field(default=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
