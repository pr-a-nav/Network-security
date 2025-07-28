from pydantic_settings import BaseSettings
from typing import Optional, List
import os


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    database_url: str = ""
    database_pool_size: int = 20
    database_max_overflow: int = 30
    database_pool_timeout: int = 30
    database_pool_recycle: int = 3600
    
    class Config:
        env_prefix = "DB_"


class SecuritySettings(BaseSettings):
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    class Config:
        env_prefix = "SECURITY_"


class ModelSettings(BaseSettings):
    model_path: str = ""
    preprocessor_path: str = ""
    model_version: str = ""
    model_update_frequency_hours: int = 24
    confidence_threshold: float = 0.8
    batch_size: int = 1000
    
    class Config:
        env_prefix = "MODEL_"


class MonitoringSettings(BaseSettings):
    enable_prometheus: bool = True
    enable_sentry: bool = True
    sentry_dsn: Optional[str] = None
    log_level: str = "INFO"
    log_format: str = "json"
    metrics_port: int = 9090
    
    class Config:
        env_prefix = "MONITORING_"


class CacheSettings(BaseSettings):
    redis_url: str = ""
    cache_ttl_seconds: int = 3600
    enable_cache: bool = True
    
    class Config:
        env_prefix = "CACHE_"


class RateLimitSettings(BaseSettings):
    enable_rate_limiting: bool = True
    requests_per_minute: int = 100
    burst_size: int = 20
    
    class Config:
        env_prefix = "RATE_LIMIT_"


class KafkaSettings(BaseSettings):
    """Kafka configuration for streaming data"""
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_network_data: str = "network-traffic"
    kafka_topic_predictions: str = "anomaly-predictions"
    kafka_group_id: str = "network-security-group"
    
    class Config:
        env_prefix = "KAFKA_"


class Settings(BaseSettings):
    app_name: str = "Network Security Anomaly Detection"
    app_version: str = "1.0.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    environment: str = "development"
    
    
    allowed_origins: List[str] = ["*"]
    allowed_methods: List[str] = ["*"]
    allowed_headers: List[str] = ["*"]
    
    database: DatabaseSettings = DatabaseSettings()
    security: SecuritySettings = SecuritySettings()
    model: ModelSettings = ModelSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    cache: CacheSettings = CacheSettings()
    rate_limit: RateLimitSettings = RateLimitSettings()
    kafka: KafkaSettings = KafkaSettings()
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()


def get_settings() -> Settings:
    return settings 