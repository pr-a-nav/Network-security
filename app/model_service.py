import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import logging
from pathlib import Path

from .preprocessor import NetworkTrafficPreprocessor, AttackCategoryMapper
from .models import NetworkTrafficData, PredictionResponse, BatchPredictionResponse

class AnomalyDetectionService:
    """Service class for anomaly detection model"""
    
    def __init__(self, model_path: str = None, preprocessor_path: str = None):
        self.model = None
        self.preprocessor = None
        self.category_mapper = AttackCategoryMapper()
        self.model_info = {}
        self.is_loaded = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load model if paths provided
        if model_path and preprocessor_path:
            self.load_model(model_path, preprocessor_path)
    
    def load_model(self, model_path: str, preprocessor_path: str) -> bool:
        """Load the trained model and preprocessor"""
        try:
            self.logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            
            self.logger.info(f"Loading preprocessor from {preprocessor_path}")
            self.preprocessor = NetworkTrafficPreprocessor.load(preprocessor_path)
            
            # Load model info if available
            model_dir = Path(model_path).parent
            info_files = list(model_dir.glob("training_info_*.json"))
            if info_files:
                import json
                with open(info_files[-1], 'r') as f:
                    self.model_info = json.load(f)
            
            self.is_loaded = True
            self.logger.info("Model and preprocessor loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            self.is_loaded = False
            return False
    
    def predict_single(self, data: NetworkTrafficData) -> PredictionResponse:
        """Predict anomaly for a single record"""
        if not self.is_loaded:
            raise ValueError("Model not loaded. Please load a trained model first.")
        
        # Convert to DataFrame
        df = pd.DataFrame([data.dict()])
        
        # Preprocess data
        processed_data = self.preprocessor.transform(df)
        
        # Make prediction
        prediction = self.model.predict(processed_data)[0]
        probability = self.model.predict_proba(processed_data)[0]
        
        # Get attack category if it's an attack
        attack_category = None
        if prediction == 1:
            # For now, we'll use a simple mapping
            # In a real scenario, you might want to predict attack categories
            attack_category = "Attack"
        
        return PredictionResponse(
            prediction=int(prediction),
            probability=float(max(probability)),
            attack_category=attack_category
        )
    
    def predict_batch(self, data_list: List[NetworkTrafficData]) -> BatchPredictionResponse:
        """Predict anomalies for multiple records"""
        if not self.is_loaded:
            raise ValueError("Model not loaded. Please load a trained model first.")
        
        # Convert to DataFrame
        df = pd.DataFrame([data.dict() for data in data_list])
        
        # Preprocess data
        processed_data = self.preprocessor.transform(df)
        
        # Make predictions
        predictions = self.model.predict(processed_data)
        probabilities = self.model.predict_proba(processed_data)
        
        # Create response objects
        prediction_responses = []
        normal_count = 0
        attack_count = 0
        
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            attack_category = None
            if pred == 1:
                attack_category = "Attack"
                attack_count += 1
            else:
                normal_count += 1
            
            response = PredictionResponse(
                prediction=int(pred),
                probability=float(max(prob)),
                attack_category=attack_category
            )
            prediction_responses.append(response)
        
        return BatchPredictionResponse(
            predictions=prediction_responses,
            total_records=len(data_list),
            normal_count=normal_count,
            attack_count=attack_count
        )
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model"""
        if not self.is_loaded:
            return {"error": "Model not loaded"}
        
        return {
            "model_name": "Anomaly Detection Model",
            "model_type": self.model_info.get("model_type", "Unknown"),
            "version": "1.0.0",
            "accuracy": self.model_info.get("metrics", {}).get("accuracy", 0.0),
            "features_count": self.model_info.get("features_count", 0),
            "last_updated": self.model_info.get("training_date", "Unknown"),
            "attack_categories": self.category_mapper.get_all_categories(),
            "is_loaded": self.is_loaded
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the model service"""
        return {
            "status": "healthy" if self.is_loaded else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "model_loaded": self.is_loaded,
            "version": "1.0.0"
        }
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the model"""
        if not self.is_loaded or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        feature_importance = dict(zip(
            self.preprocessor.feature_columns,
            self.model.feature_importances_
        ))
        
        # Sort by importance
        return dict(sorted(feature_importance.items(), 
                          key=lambda x: x[1], reverse=True)) 