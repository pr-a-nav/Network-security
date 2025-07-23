from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import pandas as pd
import asyncio
import logging
from datetime import datetime
from pathlib import Path
import json

from .streaming import StreamingDataIngestion
from .batch_processor import BatchDataProcessor, DataPipeline
from .validators import NetworkTrafficValidator, ValidationResult

# Create router
router = APIRouter(prefix="/ingestion", tags=["Data Ingestion"])

# Global instances
streaming_ingestion = None
batch_processor = None
data_pipeline = None
validator = NetworkTrafficValidator()

# Setup logging
logger = logging.getLogger(__name__)

# Pydantic models for API
from pydantic import BaseModel
from typing import List, Optional

class IngestionConfig(BaseModel):
    batch_size: int = 100
    batch_timeout: float = 5.0
    max_queue_size: int = 10000
    chunk_size: int = 10000
    max_workers: Optional[int] = None

class StreamingRecord(BaseModel):
    data: Dict[str, Any]
    source: str = "api"

class BatchProcessingRequest(BaseModel):
    file_paths: List[str]
    output_format: str = "parquet"
    validate_only: bool = False

class PipelineConfig(BaseModel):
    enable_streaming: bool = False
    enable_batch_processing: bool = True
    enable_quality_monitoring: bool = True
    auto_cleanup_temp: bool = True
    retention_days: int = 7

@router.on_event("startup")
async def startup_event():
    """Initialize ingestion components on startup"""
    global streaming_ingestion, batch_processor, data_pipeline
    
    try:
        # Initialize components
        streaming_ingestion = StreamingDataIngestion()
        batch_processor = BatchDataProcessor()
        data_pipeline = DataPipeline()
        
        logger.info("Data ingestion components initialized")
    except Exception as e:
        logger.error(f"Error initializing ingestion components: {e}")

@router.post("/streaming/start")
async def start_streaming_ingestion(config: IngestionConfig):
    """Start streaming data ingestion"""
    global streaming_ingestion
    
    try:
        if streaming_ingestion is None:
            streaming_ingestion = StreamingDataIngestion(
                batch_size=config.batch_size,
                batch_timeout=config.batch_timeout,
                max_queue_size=config.max_queue_size
            )
        
        await streaming_ingestion.start()
        
        return {
            "status": "success",
            "message": "Streaming ingestion started",
            "config": config.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/streaming/stop")
async def stop_streaming_ingestion():
    """Stop streaming data ingestion"""
    global streaming_ingestion
    
    try:
        if streaming_ingestion:
            await streaming_ingestion.stop()
            return {"status": "success", "message": "Streaming ingestion stopped"}
        else:
            return {"status": "warning", "message": "Streaming ingestion not running"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/streaming/ingest")
async def ingest_streaming_record(record: StreamingRecord):
    """Ingest a single record into streaming pipeline"""
    global streaming_ingestion
    
    if not streaming_ingestion or not streaming_ingestion.is_running:
        raise HTTPException(status_code=400, detail="Streaming ingestion not running")
    
    try:
        success = await streaming_ingestion.ingest_record(record.data, record.source)
        
        if success:
            return {"status": "success", "message": "Record ingested successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to ingest record")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/streaming/ingest/batch")
async def ingest_streaming_batch(records: List[StreamingRecord]):
    """Ingest a batch of records into streaming pipeline"""
    global streaming_ingestion
    
    if not streaming_ingestion or not streaming_ingestion.is_running:
        raise HTTPException(status_code=400, detail="Streaming ingestion not running")
    
    try:
        data_records = [record.data for record in records]
        success = await streaming_ingestion.ingest_batch(data_records, "batch_api")
        
        if success:
            return {
                "status": "success", 
                "message": f"Batch of {len(records)} records ingested successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to ingest batch")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/streaming/stats")
async def get_streaming_stats():
    """Get streaming ingestion statistics"""
    global streaming_ingestion
    
    if not streaming_ingestion:
        return {"status": "error", "message": "Streaming ingestion not initialized"}
    
    return {
        "status": "success",
        "stats": streaming_ingestion.get_stats()
    }

@router.post("/batch/process/file")
async def process_batch_file(
    file: UploadFile = File(...),
    output_format: str = "parquet",
    validate_only: bool = False
):
    """Process a single file in batch mode"""
    global batch_processor
    
    if not batch_processor:
        raise HTTPException(status_code=500, detail="Batch processor not initialized")
    
    try:
        # Save uploaded file temporarily
        temp_dir = Path("temp_uploads")
        temp_dir.mkdir(exist_ok=True)
        
        file_path = temp_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Process file
        result = batch_processor.process_file(str(file_path), output_format)
        
        # Clean up temp file
        file_path.unlink()
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/process/files")
async def process_batch_files(request: BatchProcessingRequest):
    """Process multiple files in batch mode"""
    global batch_processor
    
    if not batch_processor:
        raise HTTPException(status_code=500, detail="Batch processor not initialized")
    
    try:
        results = []
        for file_path in request.file_paths:
            if not Path(file_path).exists():
                results.append({
                    'file_path': file_path,
                    'success': False,
                    'error': 'File not found'
                })
            else:
                result = batch_processor.process_file(file_path, request.output_format)
                result['file_path'] = file_path
                results.append(result)
        
        return {
            "status": "success",
            "results": results,
            "total_files": len(request.file_paths),
            "successful_files": sum(1 for r in results if r.get('success', False))
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/batch/process/directory")
async def process_batch_directory(
    directory_path: str,
    file_pattern: str = "*.csv",
    output_format: str = "parquet"
):
    """Process all files in a directory"""
    global batch_processor
    
    if not batch_processor:
        raise HTTPException(status_code=500, detail="Batch processor not initialized")
    
    try:
        results = batch_processor.process_directory(directory_path, file_pattern)
        
        return {
            "status": "success",
            "directory": directory_path,
            "file_pattern": file_pattern,
            "results": results,
            "total_files": len(results),
            "successful_files": sum(1 for r in results if r.get('success', False))
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/validate/data")
async def validate_data(data: List[Dict[str, Any]]):
    """Validate a list of data records"""
    try:
        df = pd.DataFrame(data)
        validation_result = validator.validate_dataframe(df)
        
        return {
            "status": "success",
            "validation_result": {
                "is_valid": validation_result.is_valid,
                "valid_records": validation_result.valid_records,
                "invalid_records": validation_result.invalid_records,
                "total_records": validation_result.total_records,
                "errors": validation_result.errors[:10],  # Limit to first 10 errors
                "warnings": validation_result.warnings
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/batch/stats")
async def get_batch_stats():
    """Get batch processing statistics"""
    global batch_processor
    
    if not batch_processor:
        return {"status": "error", "message": "Batch processor not initialized"}
    
    return {
        "status": "success",
        "stats": batch_processor.stats,
        "quality_report": batch_processor.get_quality_report()
    }

@router.post("/pipeline/run")
async def run_data_pipeline(
    background_tasks: BackgroundTasks,
    config: PipelineConfig
):
    """Run the complete data pipeline"""
    global data_pipeline
    
    if not data_pipeline:
        raise HTTPException(status_code=500, detail="Data pipeline not initialized")
    
    try:
        # Update pipeline configuration
        data_pipeline.update_config(config.dict())
        
        # Run pipeline in background
        background_tasks.add_task(data_pipeline.run_pipeline)
        
        return {
            "status": "success",
            "message": "Data pipeline started in background",
            "config": config.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/pipeline/status")
async def get_pipeline_status():
    """Get current pipeline status"""
    global data_pipeline
    
    if not data_pipeline:
        return {"status": "error", "message": "Data pipeline not initialized"}
    
    return {
        "status": "success",
        "pipeline_status": data_pipeline.get_pipeline_status()
    }

@router.post("/pipeline/config")
async def update_pipeline_config(config: PipelineConfig):
    """Update pipeline configuration"""
    global data_pipeline
    
    if not data_pipeline:
        raise HTTPException(status_code=500, detail="Data pipeline not initialized")
    
    try:
        data_pipeline.update_config(config.dict())
        return {
            "status": "success",
            "message": "Pipeline configuration updated",
            "config": config.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def ingestion_health_check():
    """Health check for ingestion services"""
    global streaming_ingestion, batch_processor, data_pipeline
    
    health_status = {
        "timestamp": datetime.now().isoformat(),
        "streaming_ingestion": {
            "initialized": streaming_ingestion is not None,
            "running": streaming_ingestion.is_running if streaming_ingestion else False
        },
        "batch_processor": {
            "initialized": batch_processor is not None
        },
        "data_pipeline": {
            "initialized": data_pipeline is not None
        }
    }
    
    return health_status 