import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import train_test_split, cross_val_score
import joblib
import os
from datetime import datetime
from typing import Dict, Tuple, Any
import logging

from .preprocessor import NetworkTrafficPreprocessor, AttackCategoryMapper

class AnomalyDetectionTrainer:
    """Trainer for anomaly detection model"""
    
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.model = None
        self.preprocessor = NetworkTrafficPreprocessor()
        self.category_mapper = AttackCategoryMapper()
        self.metrics = {}
        self.training_info = {}
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def load_data(self, training_file: str, test_file: str = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load training and test data"""
        self.logger.info(f"Loading training data from {training_file}")
        train_data = pd.read_csv(training_file)
        
        if test_file:
            self.logger.info(f"Loading test data from {test_file}")
            test_data = pd.read_csv(test_file)
            return train_data, test_data
        
        # If no test file provided, split training data
        train_data, test_data = train_test_split(train_data, test_size=0.2, random_state=42)
        return train_data, test_data
    
    def prepare_data(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Prepare data for training"""
        # Separate features and target
        y = data["label"]
        X = data.drop(["label", "attack_cat"], axis=1, errors='ignore')
        
        # Remove id column if present
        if 'id' in X.columns:
            X = X.drop('id', axis=1)
        
        return X, y
    
    def train(self, training_file: str, test_file: str = None, 
              save_path: str = "models") -> Dict[str, Any]:
        """Train the anomaly detection model"""
        
        # Create save directory
        os.makedirs(save_path, exist_ok=True)
        
        # Load data
        train_data, test_data = self.load_data(training_file, test_file)
        
        # Prepare training data
        X_train, y_train = self.prepare_data(train_data)
        X_test, y_test = self.prepare_data(test_data)
        
        # Fit preprocessor
        self.logger.info("Fitting preprocessor...")
        X_train_processed = self.preprocessor.fit_transform(X_train)
        X_test_processed = self.preprocessor.transform(X_test)
        
        # Initialize and train model
        self.logger.info(f"Training {self.model_type} model...")
        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == "gradient_boosting":
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=6,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        # Train model
        self.model.fit(X_train_processed, y_train)
        
        # Evaluate model
        self.logger.info("Evaluating model...")
        self._evaluate_model(X_test_processed, y_test)
        
        # Save model and preprocessor
        self._save_model(save_path)
        
        # Store training info
        self.training_info = {
            "model_type": self.model_type,
            "training_date": datetime.now().isoformat(),
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "features_count": len(self.preprocessor.feature_columns),
            "model_parameters": self.model.get_params()
        }
        
        return {
            "metrics": self.metrics,
            "training_info": self.training_info
        }
    
    def _evaluate_model(self, X_test: pd.DataFrame, y_test: pd.Series):
        """Evaluate the trained model"""
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        self.metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='macro'),
            "recall": recall_score(y_test, y_pred, average='macro'),
            "f1_score": f1_score(y_test, y_pred, average='macro')
        }
        
        self.logger.info(f"Model Performance:")
        for metric, value in self.metrics.items():
            self.logger.info(f"{metric}: {value:.4f}")
    
    def _save_model(self, save_path: str):
        """Save the trained model and preprocessor"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = os.path.join(save_path, f"anomaly_detection_model_{timestamp}.joblib")
        joblib.dump(self.model, model_path)
        
        # Save preprocessor
        preprocessor_path = os.path.join(save_path, f"preprocessor_{timestamp}.joblib")
        self.preprocessor.save(preprocessor_path)
        
        # Save training info
        info_path = os.path.join(save_path, f"training_info_{timestamp}.json")
        import json
        with open(info_path, 'w') as f:
            json.dump(self.training_info, f, indent=2)
        
        # Save metrics
        metrics_path = os.path.join(save_path, f"metrics_{timestamp}.json")
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        self.logger.info(f"Model saved to {model_path}")
        self.logger.info(f"Preprocessor saved to {preprocessor_path}")
    
    def load_model(self, model_path: str, preprocessor_path: str):
        """Load a trained model and preprocessor"""
        self.model = joblib.load(model_path)
        self.preprocessor = NetworkTrafficPreprocessor.load(preprocessor_path)
        self.logger.info("Model and preprocessor loaded successfully")
    
    def predict(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if self.model is None:
            raise ValueError("Model not loaded. Please load a trained model first.")
        
        # Preprocess data
        data_processed = self.preprocessor.transform(data)
        
        # Make predictions
        predictions = self.model.predict(data_processed)
        probabilities = self.model.predict_proba(data_processed)
        
        return predictions, probabilities 