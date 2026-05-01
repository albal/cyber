from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    api_secret_key: str = Field(default="dev-secret-change-me")
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
