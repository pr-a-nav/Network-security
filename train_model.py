#!/usr/bin/env python3
"""
Script to train the anomaly detection model
"""

import os
import sys
import argparse
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent / "app"))

from app.model_trainer import AnomalyDetectionTrainer

def main():
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    parser.add_argument(
        "--training-file", 
        required=True,
        help="Path to training data CSV file"
    )
    parser.add_argument(
        "--test-file", 
        default=None,
        help="Path to test data CSV file (optional)"
    )
    parser.add_argument(
        "--model-type",
        choices=["random_forest", "gradient_boosting"],
        default="random_forest",
        help="Type of model to train"
    )
    parser.add_argument(
        "--save-path",
        default="models",
        help="Directory to save trained model"
    )
    
    args = parser.parse_args()
    
    # Check if training file exists
    if not os.path.exists(args.training_file):
        print(f"Error: Training file {args.training_file} not found")
        sys.exit(1)
    
    # Check if test file exists (if provided)
    if args.test_file and not os.path.exists(args.test_file):
        print(f"Error: Test file {args.test_file} not found")
        sys.exit(1)
    
    # Create save directory
    os.makedirs(args.save_path, exist_ok=True)
    
    print("Starting model training...")
    print(f"Training file: {args.training_file}")
    if args.test_file:
        print(f"Test file: {args.test_file}")
    print(f"Model type: {args.model_type}")
    print(f"Save path: {args.save_path}")
    
    try:
        # Initialize trainer
        trainer = AnomalyDetectionTrainer(model_type=args.model_type)
        
        # Train model
        results = trainer.train(
            training_file=args.training_file,
            test_file=args.test_file,
            save_path=args.save_path
        )
        
        print("\nTraining completed successfully!")
        print("\nModel Performance:")
        for metric, value in results["metrics"].items():
            print(f"{metric}: {value:.4f}")
        
        print(f"\nModel saved to: {args.save_path}")
        
    except Exception as e:
        print(f"Error during training: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 