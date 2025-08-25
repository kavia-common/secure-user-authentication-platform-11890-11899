from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
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
    site_url: str = "http://localhost:3000"
    backend_url: str = "http://localhost:8000"
    debug: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
