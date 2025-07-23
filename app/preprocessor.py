import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from typing import Dict, List, Tuple, Any
import joblib
import os

class NetworkTrafficPreprocessor:
    """Preprocessor for network traffic data"""
    
    def __init__(self):
        self.label_encoders = {}
        self.feature_columns = [
            'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
            'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt',
            'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt',
            'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
            'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
            'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
        ]
        self.categorical_columns = ['proto', 'service', 'state']
        
    def fit(self, data: pd.DataFrame) -> 'NetworkTrafficPreprocessor':
        """Fit the preprocessor on training data"""
        for col in self.categorical_columns:
            if col in data.columns:
                le = LabelEncoder()
                le.fit(data[col].astype(str))
                self.label_encoders[col] = le
        return self
    
    def transform(self, data: pd.DataFrame) -> pd.DataFrame:
        """Transform the data using fitted encoders"""
        data_transformed = data.copy()
        
        # Encode categorical variables
        for col in self.categorical_columns:
            if col in data_transformed.columns and col in self.label_encoders:
                data_transformed[col] = self.label_encoders[col].transform(
                    data_transformed[col].astype(str)
                )
        
        # Ensure all required features are present
        for col in self.feature_columns:
            if col not in data_transformed.columns:
                data_transformed[col] = 0
        
        # Select only the required features
        return data_transformed[self.feature_columns]
    
    def fit_transform(self, data: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform the data"""
        return self.fit(data).transform(data)
    
    def save(self, filepath: str):
        """Save the preprocessor to disk"""
        joblib.dump(self, filepath)
    
    @classmethod
    def load(cls, filepath: str) -> 'NetworkTrafficPreprocessor':
        """Load the preprocessor from disk"""
        return joblib.load(filepath)

class AttackCategoryMapper:
    """Mapper for attack categories"""
    
    def __init__(self):
        self.category_mapping = {
            0: "Normal",
            1: "Generic",
            2: "Exploits", 
            3: "Fuzzers",
            4: "DoS",
            5: "Reconnaissance",
            6: "Analysis",
            7: "Backdoor",
            8: "Shellcode",
            9: "Worms"
        }
    
    def get_category(self, encoded_value: int) -> str:
        """Get attack category name from encoded value"""
        return self.category_mapping.get(encoded_value, "Unknown")
    
    def get_all_categories(self) -> List[str]:
        """Get all attack categories"""
        return list(self.category_mapping.values()) 