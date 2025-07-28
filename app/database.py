from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import QueuePool
from datetime import datetime
from typing import Optional, List
import json

from .config import settings

engine = create_engine(
    settings.database.database_url,
    poolclass=QueuePool,
    pool_size=settings.database.database_pool_size,
    max_overflow=settings.database.database_max_overflow,
    pool_timeout=settings.database.database_pool_timeout,
    pool_recycle=settings.database.database_pool_recycle,
    echo=settings.debug
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    api_keys = relationship("APIKey", back_populates="user")
    predictions = relationship("Prediction", back_populates="user")
    
    __table_args__ = (
        Index('idx_users_username', 'username'),
        Index('idx_users_email', 'email'),
    )


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(255), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")


class NetworkTraffic(Base):
    __tablename__ = "network_traffic"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, index=True)
    packet_count = Column(Integer, nullable=False)
    byte_count = Column(Integer, nullable=False)
    duration = Column(Float, nullable=False)
    flags = Column(String(50))
    raw_data = Column(Text)   
    
    
    predictions = relationship("Prediction", back_populates="network_traffic")
    
    __table_args__ = (
        Index('idx_network_traffic_timestamp', 'timestamp'),
        Index('idx_network_traffic_source_ip', 'source_ip'),
        Index('idx_network_traffic_dest_ip', 'destination_ip'),
        Index('idx_network_traffic_protocol', 'protocol'),
    )


class Prediction(Base):
    __tablename__ = "predictions"
    
    id = Column(Integer, primary_key=True, index=True)
    network_traffic_id = Column(Integer, ForeignKey("network_traffic.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    model_version = Column(String(20), nullable=False)
    prediction = Column(Boolean, nullable=False, index=True)  
    confidence_score = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    feature_importance = Column(Text)  
    processing_time_ms = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    network_traffic = relationship("NetworkTraffic", back_populates="predictions")
    user = relationship("User", back_populates="predictions")
    
    __table_args__ = (
        Index('idx_predictions_created_at', 'created_at'),
        Index('idx_predictions_prediction', 'prediction'),
        Index('idx_predictions_model_version', 'model_version'),
    )


class ModelVersion(Base):
   
    __tablename__ = "model_versions"
    
    id = Column(Integer, primary_key=True, index=True)
    version = Column(String(20), unique=True, nullable=False)
    model_path = Column(String(255), nullable=False)
    preprocessor_path = Column(String(255), nullable=False)
    training_data_size = Column(Integer, nullable=False)
    training_date = Column(DateTime, nullable=False)
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    is_active = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_model_versions_version', 'version'),
        Index('idx_model_versions_is_active', 'is_active'),
    )


class Alert(Base):
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    prediction_id = Column(Integer, ForeignKey("predictions.id"), nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    alert_type = Column(String(50), nullable=False, index=True)
    message = Column(Text, nullable=False)
    is_acknowledged = Column(Boolean, default=False, index=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_alerts_severity', 'severity'),
        Index('idx_alerts_alert_type', 'alert_type'),
        Index('idx_alerts_is_acknowledged', 'is_acknowledged'),
        Index('idx_alerts_created_at', 'created_at'),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(50), nullable=True)
    details = Column(Text)  # JSON string of additional details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_logs_user_id', 'user_id'),
        Index('idx_audit_logs_action', 'action'),
        Index('idx_audit_logs_resource_type', 'resource_type'),
        Index('idx_audit_logs_created_at', 'created_at'),
    )


class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    cpu_usage = Column(Float, nullable=False)
    memory_usage = Column(Float, nullable=False)
    disk_usage = Column(Float, nullable=False)
    network_io = Column(Float, nullable=False)
    active_connections = Column(Integer, nullable=False)
    requests_per_second = Column(Float, nullable=False)
    average_response_time = Column(Float, nullable=False)
    
    __table_args__ = (
        Index('idx_system_metrics_timestamp', 'timestamp'),
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


n
def init_db():
    Base.metadata.create_all(bind=engine)


def drop_db():
    Base.metadata.drop_all(bind=engine) 