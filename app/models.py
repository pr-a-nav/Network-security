from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import numpy as np

class NetworkTrafficData(BaseModel):
    """Model for single network traffic record"""
    id: int
    dur: float = Field(..., ge=0, description="Duration of the flow")
    proto: str = Field(..., description="Protocol type")
    service: str = Field(..., description="Service type")
    state: str = Field(..., description="Connection state")
    spkts: int = Field(..., ge=0, description="Source packets")
    dpkts: int = Field(..., ge=0, description="Destination packets")
    sbytes: int = Field(..., ge=0, description="Source bytes")
    dbytes: int = Field(..., ge=0, description="Destination bytes")
    rate: float = Field(..., description="Flow rate")
    sttl: int = Field(..., ge=0, le=255, description="Source TTL")
    dttl: int = Field(..., ge=0, le=255, description="Destination TTL")
    sload: float = Field(..., description="Source load")
    dload: float = Field(..., description="Destination load")
    sloss: int = Field(..., ge=0, description="Source loss")
    dloss: int = Field(..., ge=0, description="Destination loss")
    sinpkt: float = Field(..., description="Source inter-packet time")
    dinpkt: float = Field(..., description="Destination inter-packet time")
    sjit: float = Field(..., description="Source jitter")
    djit: float = Field(..., description="Destination jitter")
    swin: int = Field(..., ge=0, description="Source window size")
    stcpb: int = Field(..., ge=0, description="Source TCP base sequence number")
    dtcpb: int = Field(..., ge=0, description="Destination TCP base sequence number")
    dwin: int = Field(..., ge=0, description="Destination window size")
    tcprtt: float = Field(..., description="TCP round trip time")
    synack: float = Field(..., description="SYN-ACK time")
    ackdat: float = Field(..., description="ACK data time")
    smean: int = Field(..., ge=0, description="Source mean")
    dmean: int = Field(..., ge=0, description="Destination mean")
    trans_depth: int = Field(..., ge=0, description="Transaction depth")
    response_body_len: int = Field(..., ge=0, description="Response body length")
    ct_srv_src: int = Field(..., ge=0, description="Connection state service source")
    ct_state_ttl: int = Field(..., ge=0, description="Connection state TTL")
    ct_dst_ltm: int = Field(..., ge=0, description="Connection destination last time")
    ct_src_dport_ltm: int = Field(..., ge=0, description="Connection source destination port last time")
    ct_dst_sport_ltm: int = Field(..., ge=0, description="Connection destination source port last time")
    ct_dst_src_ltm: int = Field(..., ge=0, description="Connection destination source last time")
    is_ftp_login: int = Field(..., ge=0, le=1, description="Is FTP login")
    ct_ftp_cmd: int = Field(..., ge=0, description="Connection FTP command")
    ct_flw_http_mthd: int = Field(..., ge=0, description="Connection flow HTTP method")
    ct_src_ltm: int = Field(..., ge=0, description="Connection source last time")
    ct_srv_dst: int = Field(..., ge=0, description="Connection service destination")
    is_sm_ips_ports: int = Field(..., ge=0, le=1, description="Is same IPs and ports")

class BatchNetworkTrafficData(BaseModel):
    """Model for batch network traffic records"""
    records: List[NetworkTrafficData]

class PredictionResponse(BaseModel):
    """Model for prediction response"""
    prediction: int = Field(..., description="Predicted label (0: Normal, 1: Attack)")
    probability: float = Field(..., ge=0, le=1, description="Prediction probability")
    attack_category: Optional[str] = Field(None, description="Attack category if attack detected")

class BatchPredictionResponse(BaseModel):
    """Model for batch prediction response"""
    predictions: List[PredictionResponse]
    total_records: int
    normal_count: int
    attack_count: int

class ModelInfo(BaseModel):
    """Model for model information response"""
    model_name: str
    model_type: str
    version: str
    accuracy: float
    features_count: int
    last_updated: str
    attack_categories: List[str]

class HealthResponse(BaseModel):
    """Model for health check response"""
    status: str
    timestamp: str
    model_loaded: bool
    version: str 