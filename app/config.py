from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql://csw:csw@localhost:5432/csw"
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    first_admin_username: str = "admin"
    first_admin_password: str = Field(
        default="changeme",
        validation_alias=AliasChoices("ADMIN_PASSWORD", "FIRST_ADMIN_PASSWORD"),
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
