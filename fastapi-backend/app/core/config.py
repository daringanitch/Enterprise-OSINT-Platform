"""
Application configuration using Pydantic Settings
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseSettings, validator
from pydantic import PostgresDsn, RedisDsn
from functools import lru_cache
import secrets


class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Enterprise OSINT Platform"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "osint_audit"
    DATABASE_URL: Optional[PostgresDsn] = None
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )
    
    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: Optional[RedisDsn] = None
    
    @validator("REDIS_URL", pre=True)
    def assemble_redis_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return RedisDsn.build(
            scheme="redis",
            host=values.get("REDIS_HOST"),
            port=str(values.get("REDIS_PORT")),
            path=f"/{values.get('REDIS_DB') or 0}",
        )
    
    # Celery Configuration
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CELERY_TASK_ALWAYS_EAGER: bool = False  # Set True for testing
    CELERY_TASK_EAGER_PROPAGATES: bool = True
    CELERY_TASK_TIME_LIMIT: int = 3600  # 1 hour
    CELERY_TASK_SOFT_TIME_LIMIT: int = 3300  # 55 minutes
    CELERY_WORKER_PREFETCH_MULTIPLIER: int = 4
    CELERY_WORKER_MAX_TASKS_PER_CHILD: int = 1000
    
    @validator("CELERY_BROKER_URL", pre=True)
    def set_celery_broker(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if v:
            return v
        return values.get("REDIS_URL") or f"redis://{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB', 0)}"
    
    @validator("CELERY_RESULT_BACKEND", pre=True)
    def set_celery_backend(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if v:
            return v
        return values.get("REDIS_URL") or f"redis://{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB', 0)}"
    
    # Task Queue Settings
    TASK_MAX_RETRIES: int = 3
    TASK_RETRY_DELAY: int = 60  # seconds
    TASK_RETRY_BACKOFF: float = 2.0
    TASK_RETRY_JITTER: bool = True
    TASK_RATE_LIMIT: str = "100/m"  # 100 tasks per minute
    
    # External APIs
    OPENAI_API_KEY: Optional[str] = None
    TWITTER_BEARER_TOKEN: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    
    # MCP Server URLs
    MCP_SOCIAL_MEDIA_URL: str = "http://mcp-social-media:8010"
    MCP_INFRASTRUCTURE_URL: str = "http://mcp-infrastructure:8020"
    MCP_THREAT_INTEL_URL: str = "http://mcp-threat-intel:8030"
    
    # Vault Configuration
    VAULT_ADDR: str = "http://vault:8200"
    VAULT_TOKEN: Optional[str] = None
    VAULT_NAMESPACE: Optional[str] = None
    USE_VAULT: bool = True
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_STORAGE_URL: Optional[str] = None
    
    @validator("RATE_LIMIT_STORAGE_URL", pre=True)
    def set_rate_limit_storage(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if v:
            return v
        return values.get("REDIS_URL") or f"redis://{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB', 1)}"
    
    # Monitoring
    SENTRY_DSN: Optional[str] = None
    PROMETHEUS_ENABLED: bool = True
    OPENTELEMETRY_ENABLED: bool = False
    
    # Investigation Settings
    MAX_CONCURRENT_INVESTIGATIONS: int = 10
    INVESTIGATION_TIMEOUT: int = 3600  # 1 hour
    MAX_INVESTIGATION_DEPTH: int = 3
    
    # Report Generation
    REPORT_STORAGE_PATH: str = "/app/reports"
    REPORT_RETENTION_DAYS: int = 30
    MAX_REPORT_SIZE_MB: int = 50
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Export settings instance
settings = get_settings()