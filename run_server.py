#!/usr/bin/env python3
"""
Script to run the FastAPI server
"""

import uvicorn
import os
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Run anomaly detection API server")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind the server to"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the server to"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes"
    )
    
    args = parser.parse_args()
    
    print("Starting Anomaly Detection API Server...")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Reload: {args.reload}")
    print(f"Workers: {args.workers}")
    print(f"API Documentation: http://{args.host}:{args.port}/docs")
    print(f"ReDoc Documentation: http://{args.host}:{args.port}/redoc")
    
    # Set environment variables for model paths
    if not os.getenv("MODEL_PATH"):
        os.environ["MODEL_PATH"] = "models/anomaly_detection_model.joblib"
    if not os.getenv("PREPROCESSOR_PATH"):
        os.environ["PREPROCESSOR_PATH"] = "models/preprocessor.joblib"
    
    # Run the server
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if args.workers > 1 else None,
        log_level="info"
    )

if __name__ == "__main__":
    main() 