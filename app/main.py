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

# Initialize FastAPI app
app = FastAPI(
    title="Network Anomaly Detection API",
    description="API for detecting network traffic anomalies using machine learning with scalable data ingestion",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model service instance
model_service = None

def get_model_service() -> AnomalyDetectionService:
    """Dependency to get model service instance"""
    global model_service
    if model_service is None:
        # Try to load model from default paths
        model_path = os.getenv("MODEL_PATH", "models/anomaly_detection_model.joblib")
        preprocessor_path = os.getenv("PREPROCESSOR_PATH", "models/preprocessor.joblib")
        
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
    """Initialize model service on startup"""
    global model_service
    try:
        model_service = AnomalyDetectionService()
        model_path = os.getenv("MODEL_PATH", "models/anomaly_detection_model.joblib")
        preprocessor_path = os.getenv("PREPROCESSOR_PATH", "models/preprocessor.joblib")
        
        if os.path.exists(model_path) and os.path.exists(preprocessor_path):
            model_service.load_model(model_path, preprocessor_path)
    except Exception as e:
        print(f"Warning: Could not load model on startup: {e}")

# Include data ingestion routes
app.include_router(ingestion_router)

@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "message": "Network Anomaly Detection API with Data Ingestion",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "prediction": "/predict",
            "batch_prediction": "/predict/batch",
            "model_info": "/model/info",
            "data_ingestion": "/ingestion",
            "streaming": "/ingestion/streaming",
            "batch_processing": "/ingestion/batch"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    service = get_model_service()
    health_info = service.health_check()
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
        model_path = os.getenv("MODEL_PATH", "models/anomaly_detection_model.joblib")
        preprocessor_path = os.getenv("PREPROCESSOR_PATH", "models/preprocessor.joblib")
        
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
    return {
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model_service.is_loaded if model_service else False,
        "endpoints": [
            "/",
            "/health",
            "/model/info",
            "/predict",
            "/predict/batch",
            "/features/importance",
            "/model/reload",
            "/stats",
            "/ingestion/*"
        ]
    }

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
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 