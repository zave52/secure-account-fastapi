from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure Account"
    secret_key: str = "development-only-change-me"
    database_url: str = "sqlite+aiosqlite:///./security.db"
    session_ttl_minutes: int = 60 * 24 * 7
    token_ttl_hours: int = 24
    captcha_ttl_seconds: int = 300
    cloudflare_turnstile_site_key: str | None = None
    cloudflare_turnstile_secret_key: str | None = None
    cloudflare_turnstile_enabled: bool = False
    max_login_attempts: int = 5
    lockout_minutes: int = 15
    cookie_secure: bool = False
    admin_email: str = "admin@example.com"
    admin_password: str = "Admin!2026#Secure"
    google_client_id: str | None = None
    google_client_secret: str | None = None
    github_client_id: str | None = None
    github_client_secret: str | None = None
    oauth_redirect_base_url: str | None = None
    smtp_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_from_name: str = "Secure Account"
    smtp_starttls: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
