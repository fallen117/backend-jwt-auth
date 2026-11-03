from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Backend JWT"

    # Base de datos
    database_url: str
    db_pool_min_size: int = 1
    db_pool_max_size: int = 10

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "backend-jwt"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Seguridad de login
    max_failed_login_attempts: int = 5
    lockout_minutes: int = 15
    require_verified_email: bool = False
    allow_registration: bool = True
    default_role: str = "viewer"
    verification_token_expire_hours: int = 24
    password_reset_expire_minutes: int = 60

    # Otros
    expose_debug_tokens: bool = False
    cors_origins: str = "http://localhost:3000"

    @field_validator("jwt_secret_key")
    @classmethod
    def _secret_long_enough(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY debe tener al menos 32 caracteres")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
