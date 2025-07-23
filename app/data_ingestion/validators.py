import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import logging
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Result of data validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    valid_records: int
    invalid_records: int
    total_records: int

class NetworkTrafficValidator:
    """Validator for network traffic data"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define expected data types and ranges
        self.field_specs = {
            'dur': {'type': float, 'min': 0, 'max': 3600},  # Duration in seconds
            'proto': {'type': str, 'allowed_values': ['tcp', 'udp', 'icmp', 'http', 'https', 'ftp', 'ssh']},
            'service': {'type': str},
            'state': {'type': str, 'allowed_values': ['FIN', 'INT', 'CON', 'REQ', 'RST', 'ACC', 'CLO']},
            'spkts': {'type': int, 'min': 0, 'max': 100000},
            'dpkts': {'type': int, 'min': 0, 'max': 100000},
            'sbytes': {'type': int, 'min': 0, 'max': 1000000000},
            'dbytes': {'type': int, 'min': 0, 'max': 1000000000},
            'rate': {'type': float, 'min': 0, 'max': 1000000},
            'sttl': {'type': int, 'min': 0, 'max': 255},
            'dttl': {'type': int, 'min': 0, 'max': 255},
            'sload': {'type': float, 'min': 0},
            'dload': {'type': float, 'min': 0},
            'sloss': {'type': int, 'min': 0},
            'dloss': {'type': int, 'min': 0},
            'sinpkt': {'type': float, 'min': 0},
            'dinpkt': {'type': float, 'min': 0},
            'sjit': {'type': float, 'min': 0},
            'djit': {'type': float, 'min': 0},
            'swin': {'type': int, 'min': 0, 'max': 65535},
            'stcpb': {'type': int, 'min': 0},
            'dtcpb': {'type': int, 'min': 0},
            'dwin': {'type': int, 'min': 0, 'max': 65535},
            'tcprtt': {'type': float, 'min': 0},
            'synack': {'type': float, 'min': 0},
            'ackdat': {'type': float, 'min': 0},
            'smean': {'type': int, 'min': 0},
            'dmean': {'type': int, 'min': 0},
            'trans_depth': {'type': int, 'min': 0},
            'response_body_len': {'type': int, 'min': 0},
            'ct_srv_src': {'type': int, 'min': 0},
            'ct_state_ttl': {'type': int, 'min': 0},
            'ct_dst_ltm': {'type': int, 'min': 0},
            'ct_src_dport_ltm': {'type': int, 'min': 0},
            'ct_dst_sport_ltm': {'type': int, 'min': 0},
            'ct_dst_src_ltm': {'type': int, 'min': 0},
            'is_ftp_login': {'type': int, 'min': 0, 'max': 1},
            'ct_ftp_cmd': {'type': int, 'min': 0},
            'ct_flw_http_mthd': {'type': int, 'min': 0},
            'ct_src_ltm': {'type': int, 'min': 0},
            'ct_srv_dst': {'type': int, 'min': 0},
            'is_sm_ips_ports': {'type': int, 'min': 0, 'max': 1}
        }
    
    def validate_single_record(self, record: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a single network traffic record"""
        errors = []
        
        for field, value in record.items():
            if field not in self.field_specs:
                continue
                
            spec = self.field_specs[field]
            
            # Check data type
            if not isinstance(value, spec['type']):
                try:
                    # Try to convert
                    if spec['type'] == float:
                        value = float(value)
                    elif spec['type'] == int:
                        value = int(value)
                    elif spec['type'] == str:
                        value = str(value)
                except (ValueError, TypeError):
                    errors.append(f"Invalid type for {field}: expected {spec['type'].__name__}, got {type(value).__name__}")
                    continue
            
            # Check range constraints
            if 'min' in spec and value < spec['min']:
                errors.append(f"{field} value {value} is below minimum {spec['min']}")
            
            if 'max' in spec and value > spec['max']:
                errors.append(f"{field} value {value} is above maximum {spec['max']}")
            
            # Check allowed values
            if 'allowed_values' in spec and value not in spec['allowed_values']:
                errors.append(f"{field} value '{value}' is not in allowed values: {spec['allowed_values']}")
        
        return len(errors) == 0, errors
    
    def validate_dataframe(self, df: pd.DataFrame) -> ValidationResult:
        """Validate a pandas DataFrame of network traffic data"""
        errors = []
        warnings = []
        valid_records = 0
        invalid_records = 0
        
        # Check for missing required columns
        required_columns = list(self.field_specs.keys())
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            warnings.append(f"Missing columns: {missing_columns}")
        
        # Validate each record
        for idx, row in df.iterrows():
            record = row.to_dict()
            is_valid, record_errors = self.validate_single_record(record)
            
            if is_valid:
                valid_records += 1
            else:
                invalid_records += 1
                for error in record_errors:
                    errors.append(f"Row {idx}: {error}")
        
        # Check for data quality issues
        quality_warnings = self._check_data_quality(df)
        warnings.extend(quality_warnings)
        
        total_records = len(df)
        is_valid = invalid_records == 0
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            valid_records=valid_records,
            invalid_records=invalid_records,
            total_records=total_records
        )
    
    def _check_data_quality(self, df: pd.DataFrame) -> List[str]:
        """Check for data quality issues"""
        warnings = []
        
        # Check for missing values
        missing_counts = df.isnull().sum()
        for col, count in missing_counts.items():
            if count > 0:
                percentage = (count / len(df)) * 100
                warnings.append(f"Column {col} has {count} ({percentage:.1f}%) missing values")
        
        # Check for duplicate records
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            warnings.append(f"Found {duplicates} duplicate records")
        
        # Check for outliers in numeric columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if col in self.field_specs:
                Q1 = df[col].quantile(0.25)
                Q3 = df[col].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR
                
                outliers = df[(df[col] < lower_bound) | (df[col] > upper_bound)]
                if len(outliers) > 0:
                    warnings.append(f"Column {col} has {len(outliers)} potential outliers")
        
        return warnings

class DataQualityMonitor:
    """Monitor data quality over time"""
    
    def __init__(self):
        self.quality_metrics = []
        self.logger = logging.getLogger(__name__)
    
    def record_validation(self, validation_result: ValidationResult, timestamp: datetime = None):
        """Record validation results for monitoring"""
        if timestamp is None:
            timestamp = datetime.now()
        
        metric = {
            'timestamp': timestamp,
            'total_records': validation_result.total_records,
            'valid_records': validation_result.valid_records,
            'invalid_records': validation_result.invalid_records,
            'error_count': len(validation_result.errors),
            'warning_count': len(validation_result.warnings),
            'quality_score': validation_result.valid_records / validation_result.total_records if validation_result.total_records > 0 else 0
        }
        
        self.quality_metrics.append(metric)
        
        # Keep only last 1000 metrics to prevent memory issues
        if len(self.quality_metrics) > 1000:
            self.quality_metrics = self.quality_metrics[-1000:]
    
    def get_quality_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get quality summary for the last N hours"""
        if not self.quality_metrics:
            return {}
        
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        recent_metrics = [
            m for m in self.quality_metrics 
            if m['timestamp'].timestamp() > cutoff_time
        ]
        
        if not recent_metrics:
            return {}
        
        total_records = sum(m['total_records'] for m in recent_metrics)
        valid_records = sum(m['valid_records'] for m in recent_metrics)
        error_count = sum(m['error_count'] for m in recent_metrics)
        
        return {
            'period_hours': hours,
            'total_records': total_records,
            'valid_records': valid_records,
            'invalid_records': total_records - valid_records,
            'overall_quality_score': valid_records / total_records if total_records > 0 else 0,
            'total_errors': error_count,
            'average_quality_score': np.mean([m['quality_score'] for m in recent_metrics])
        } 