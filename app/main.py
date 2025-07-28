from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
from datetime import datetime
from typing import List

from .models import (
    NetworkTrafficData, 
    BatchNetworkTrafficData,
    PredictionResponse, 
    BatchPredictionResponse,
    ModelInfo,
    HealthResponse
)
from .model_service import AnomalyDetectionService
from .data_ingestion.api import router as ingestion_router
from .api.network_capture_routes import router as capture_router
from .config import settings
from .monitoring import MonitoringMiddleware, get_metrics_service
from .rate_limiter import RateLimitMiddleware
from .cache import get_cache_service

# Initialize FastAPI app
app = FastAPI(
    title="Network Security Anomaly Detection API",
    description="Enterprise-grade API for detecting network traffic anomalies using machine learning with real-time capture and scalable data ingestion",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add middleware
app.add_middleware(MonitoringMiddleware)
app.add_middleware(RateLimitMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=settings.allowed_methods,
    allow_headers=settings.allowed_headers,
)

# Global model service instance
model_service = None

def get_model_service() -> AnomalyDetectionService:
    """Dependency to get model service instance"""
    global model_service
    if model_service is None:
        # Try to load model from default paths
        model_path = settings.model.model_path
        preprocessor_path = settings.model.preprocessor_path
        
        model_service = AnomalyDetectionService()
        if os.path.exists(model_path) and os.path.exists(preprocessor_path):
            model_service.load_model(model_path, preprocessor_path)
        else:
            raise HTTPException(
                status_code=500,
                detail="Model files not found. Please ensure model is trained and saved."
            )
    
    return model_service

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global model_service
    try:
        # Initialize model service
        model_service = AnomalyDetectionService()
        model_path = settings.model.model_path
        preprocessor_path = settings.model.preprocessor_path
        
        if os.path.exists(model_path) and os.path.exists(preprocessor_path):
            model_service.load_model(model_path, preprocessor_path)
            print(f"Model loaded successfully: {settings.model.model_version}")
        
        # Initialize cache service
        cache_service = get_cache_service()
        print(f"Cache service initialized: {cache_service.get_stats()}")
        
        # Initialize metrics service
        metrics_service = get_metrics_service()
        print(f"Metrics service initialized")
        
    except Exception as e:
        print(f"Warning: Could not initialize services on startup: {e}")

# Include routers
app.include_router(ingestion_router)
app.include_router(capture_router)

@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "message": "Network Security Anomaly Detection API with Real-time Capture",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "prediction": "/predict",
            "batch_prediction": "/predict/batch",
            "model_info": "/model/info",
            "data_ingestion": "/ingestion",
            "streaming": "/ingestion/streaming",
            "batch_processing": "/ingestion/batch",
            "network_capture": "/capture",
            "realtime_processing": "/capture/realtime",
            "live_streaming": "/capture/ws/live",
            "anomaly_streaming": "/capture/ws/anomalies"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    service = get_model_service()
    health_info = service.health_check()
    
    # Add additional health checks
    from .network_capture import get_network_capture_service
    from .real_time_processor import get_real_time_processor
    
    capture_service = get_network_capture_service()
    processor = get_real_time_processor()
    
    health_info.update({
        "capture_service": {
            "available": True,
            "is_capturing": capture_service.is_capturing,
            "interfaces_available": len(capture_service.available_interfaces)
        },
        "real_time_processor": {
            "available": True,
            "is_processing": processor.is_processing,
            "model_loaded": processor.model_service.is_loaded
        }
    })
    
    return HealthResponse(**health_info)

@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    """Get model information"""
    service = get_model_service()
    info = service.get_model_info()
    return ModelInfo(**info)

@app.post("/predict", response_model=PredictionResponse)
async def predict_single(data: NetworkTrafficData):
    """Predict anomaly for a single network traffic record"""
    try:
        service = get_model_service()
        result = service.predict_single(data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(data: BatchNetworkTrafficData):
    """Predict anomalies for multiple network traffic records"""
    try:
        service = get_model_service()
        result = service.predict_batch(data.records)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/features/importance")
async def get_feature_importance():
    """Get feature importance from the model"""
    try:
        service = get_model_service()
        importance = service.get_feature_importance()
        return {"feature_importance": importance}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/model/reload")
async def reload_model():
    """Reload the model from disk"""
    try:
        global model_service
        model_path = settings.model.model_path
        preprocessor_path = settings.model.preprocessor_path
        
        model_service = AnomalyDetectionService()
        success = model_service.load_model(model_path, preprocessor_path)
        
        if success:
            return {"message": "Model reloaded successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to reload model")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    """Get API statistics"""
    from .network_capture import get_network_capture_service
    from .real_time_processor import get_real_time_processor
    
    capture_service = get_network_capture_service()
    processor = get_real_time_processor()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model_service.is_loaded if model_service else False,
        "capture_statistics": capture_service.get_statistics(),
        "processing_statistics": processor.get_statistics(),
        "endpoints": [
            "/",
            "/health",
            "/model/info",
            "/predict",
            "/predict/batch",
            "/features/importance",
            "/model/reload",
            "/stats",
            "/ingestion/*",
            "/capture/*"
        ]
    }

@app.get("/metrics")
async def get_metrics():
    """Get Prometheus metrics"""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response
    
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.monitoring.log_level.lower()
    ) 