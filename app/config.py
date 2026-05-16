from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Core
    env: str = Field(default="dev", validation_alias=AliasChoices("ENV"))
    secret_key: str = "change-me-in-production"
    webui_secret_key: str = ""  # Fernet master key for secrets at rest (required outside dev)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    # Admin bootstrap
    first_admin_username: str = "admin"
    first_admin_password: str = Field(
        default="changeme",
        validation_alias=AliasChoices("ADMIN_PASSWORD", "FIRST_ADMIN_PASSWORD"),
    )

    # Data directory
    data_dir: str = "./data"

    # TLS
    tls_cert_path: str = ""   # override path; auto-generated if empty
    tls_key_path: str = ""    # override path; auto-generated if empty

    # Auth provider stubs (inactive for now)
    oidc_enabled: bool = False
    oidc_discovery_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""

    ldap_enabled: bool = False
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_user_search_base: str = ""

    radius_enabled: bool = False
    radius_host: str = ""
    radius_port: int = 1812
    radius_secret: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    def data_path(self) -> Path:
        return Path(self.data_dir)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    is_dev = str(settings.env or "").strip().lower() == "dev"
    if not settings.webui_secret_key and not is_dev:
        raise RuntimeError("WEBUI_SECRET_KEY must be set in production")
    if settings.secret_key == "change-me-in-production" and not is_dev:
        raise RuntimeError("SECRET_KEY must be set in production (used for JWT signing)")
    return settings
