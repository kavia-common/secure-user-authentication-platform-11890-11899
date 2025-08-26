from typing import List
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables.
    
    Note: All configuration is sourced from environment variables via .env.
    Never hardcode secrets in code. Update the project's .env (or environment)
    to adjust runtime behavior.
    """
    # Supabase Configuration
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str

    # JWT Configuration
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Email Configuration
    email_from: str
    email_smtp_host: str
    email_smtp_port: int = 587
    email_smtp_user: str
    email_smtp_password: str

    # Application Configuration
    # SITE_URL is the public site URL for the frontend (used in email links and CORS).
    # Default to local dev frontend.
    site_url: AnyHttpUrl | str = "http://localhost:3000"
    # BACKEND_URL is the externally reachable backend base URL (used in email links and metadata).
    backend_url: AnyHttpUrl | str = "http://localhost:8000"
    debug: bool = True

    @field_validator("site_url", "backend_url")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        """Normalize URLs by removing a trailing slash for consistent joins."""
        try:
            return v.rstrip("/")
        except Exception:
            return v

    @property
    def allowed_cors_origins(self) -> List[str]:
        """Built list of allowed origins for CORS based on env and local dev defaults."""
        base_origins = {
            str(self.site_url),
            "http://localhost:3000",
            "http://localhost:3001",
            "https://localhost:3000",
            "https://localhost:3001",
        }
        # Ensure no None/empty values
        return [o for o in base_origins if o]

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
