import asyncio
import threading
import time
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json
import statistics

from .network_capture import NetworkPacket, get_network_capture_service
from .model_service import AnomalyDetectionService
from .database import get_db, NetworkTraffic, Prediction, Alert
from .monitoring import logger, get_metrics_service
from .config import settings


class RealTimeProcessor:
    
    def __init__(self):
        self.model_service = AnomalyDetectionService()
        self.capture_service = get_network_capture_service()
        self.metrics_service = get_metrics_service()
        
        self.is_processing = False
        self.processing_thread = None
        
        self.batch_size = settings.model.batch_size
        self.batch_timeout = 5.0 
        self.packet_batch = deque()
        self.last_batch_time = time.time()
        
        
        self.packets_processed = 0
        self.anomalies_detected = 0
        self.processing_times = deque(maxlen=1000)
        self.start_time = None
        
        self.alert_thresholds = {
            'confidence_threshold': settings.model.confidence_threshold,
            'anomaly_rate_threshold': 0.1,  
            'burst_threshold': 100,  
        }
        
        
        self.packet_rates = defaultdict(lambda: deque(maxlen=60))  # 1 minute window
        self.anomaly_rates = defaultdict(lambda: deque(maxlen=60))
        
        self.anomaly_callbacks = []
        self.alert_callbacks = []
        self.statistics_callbacks = []
    
    def start_processing(self, interface: str = None, filter: str = None):
        if self.is_processing:
            logger.warning("Real-time processing already running")
            return False
        
        if not self.model_service.is_loaded:
            model_path = settings.model.model_path
            preprocessor_path = settings.model.preprocessor_path
            if not self.model_service.load_model(model_path, preprocessor_path):
                logger.error("Failed to load model for real-time processing")
                return False
        
        
        if not self.capture_service.start_capture(interface, filter):
            logger.error("Failed to start network capture")
            return False
        
        
        self.capture_service.add_callback(self._process_packet)
        
        
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True
        )
        self.processing_thread.start()
        
        self.is_processing = True
        self.start_time = datetime.utcnow()
        self.packets_processed = 0
        self.anomalies_detected = 0
        
        logger.info("Real-time processing started")
        return True
    
    def stop_processing(self):
        if not self.is_processing:
            return
        
        logger.info("Stopping real-time processing")
        
        self.capture_service.stop_capture()
        
        self.is_processing = False
        
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        self._process_batch()
        
        logger.info(f"Real-time processing stopped. Processed: {self.packets_processed}, Anomalies: {self.anomalies_detected}")
    
    def _process_packet(self, packet: NetworkPacket):
        if not self.is_processing:
            return
        
        self.packet_batch.append(packet)
        
        current_time = time.time()
        self.packet_rates[packet.source_ip].append(current_time)
        
        if (len(self.packet_batch) >= self.batch_size or 
            current_time - self.last_batch_time >= self.batch_timeout):
            self._process_batch()
    
    def _process_batch(self):
        
        if not self.packet_batch:
            return
        
        start_time = time.time()
        
        try:
            features_list = []
            packets_list = list(self.packet_batch)
            
            for packet in packets_list:
                features = self._extract_features(packet)
                if features:
                    features_list.append(features)
            
            if not features_list:
                return
            
            predictions = self.model_service.predict_batch_features(features_list)
            
            for i, (packet, prediction) in enumerate(zip(packets_list, predictions)):
                self._handle_prediction_result(packet, prediction)
            
            processing_time = time.time() - start_time
            self.processing_times.append(processing_time)
            self.packets_processed += len(packets_list)
            
            self.metrics_service.record_prediction(
                model_version=settings.model.model_version,
                prediction_type="batch",
                duration=processing_time
            )
            
            self.packet_batch.clear()
            self.last_batch_time = time.time()
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
            self.packet_batch.clear()
    
    def _extract_features(self, packet: NetworkPacket) -> Optional[Dict[str, Any]]:
        try:
            features = {
                'source_ip': packet.source_ip,
                'destination_ip': packet.destination_ip,
                'source_port': packet.source_port or 0,
                'destination_port': packet.destination_port or 0,
                'protocol': packet.protocol or 'UNKNOWN',
                'packet_size': packet.packet_size,
                'payload_size': packet.payload_size,
                'ttl': packet.ttl or 64,
                'window_size': packet.window_size or 0,
            }
            
            if packet.protocol == 'TCP':
                features.update({
                    'tcp_flags': self._parse_tcp_flags(packet.flags),
                    'tcp_window_size': packet.window_size or 0,
                })
            elif packet.protocol == 'UDP':
                features.update({
                    'udp_length': packet.payload_size,
                })
            elif packet.protocol == 'ICMP':
                features.update({
                    'icmp_type': self._parse_icmp_type(packet.flags),
                })
            
            features.update(self._get_network_behavior_features(packet))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _parse_tcp_flags(self, flags: str) -> int:
        if not flags:
            return 0
        
        flag_map = {
            'F': 1,    # FIN
            'S': 2,    # SYN
            'R': 4,    # RST
            'P': 8,    # PSH
            'A': 16,   # ACK
            'U': 32,   # URG
        }
        
        total = 0
        for flag in flags:
            total += flag_map.get(flag, 0)
        return total
    
    def _parse_icmp_type(self, icmp_type: str) -> int:
        try:
            return int(icmp_type) if icmp_type else 0
        except:
            return 0
    
    def _get_network_behavior_features(self, packet: NetworkPacket) -> Dict[str, Any]:
        
        features = {}
        
       
        source_ip = packet.source_ip
        if source_ip:
            #
            current_time = time.time()
            recent_packets = [t for t in self.packet_rates[source_ip] 
                            if current_time - t <= 60]  # Last minute
            
            features.update({
                'packets_per_second': len(recent_packets) / 60.0,
                'burst_rate': len([t for t in recent_packets if current_time - t <= 1]) / 1.0,
            })
        
        if packet.destination_port:
            features.update({
                'is_well_known_port': packet.destination_port <= 1024,
                'is_privileged_port': packet.source_port <= 1024 if packet.source_port else False,
            })
        
        features.update({
            'is_large_packet': packet.packet_size > 1500,
            'is_small_packet': packet.packet_size < 64,
            'payload_ratio': packet.payload_size / max(packet.packet_size, 1),
        })
        
        return features
    
    def _handle_prediction_result(self, packet: NetworkPacket, prediction: Dict[str, Any]):
        try:
            is_anomaly = prediction.get('prediction', False)
            confidence = prediction.get('confidence', 0.0)
            anomaly_score = prediction.get('anomaly_score', 0.0)
            
            if is_anomaly:
                self.anomalies_detected += 1
                self.anomaly_rates[packet.source_ip].append(time.time())
            
            self._store_prediction(packet, prediction)
            
            if is_anomaly and confidence >= self.alert_thresholds['confidence_threshold']:
                self._create_alert(packet, prediction)
            
            if is_anomaly:
                for callback in self.anomaly_callbacks:
                    try:
                        callback(packet, prediction)
                    except Exception as e:
                        logger.error(f"Error in anomaly callback: {e}")
            
        except Exception as e:
            logger.error(f"Error handling prediction result: {e}")
    
    def _store_prediction(self, packet: NetworkPacket, prediction: Dict[str, Any]):
        try:
            db = next(get_db())
            
            # Create network traffic record
            network_traffic = packet.to_network_traffic_model()
            db.add(network_traffic)
            db.flush()  # Get the ID
            
            # Create prediction record
            prediction_record = Prediction(
                network_traffic_id=network_traffic.id,
                model_version=settings.model.model_version,
                prediction=prediction.get('prediction', False),
                confidence_score=prediction.get('confidence', 0.0),
                anomaly_score=prediction.get('anomaly_score', 0.0),
                feature_importance=json.dumps(prediction.get('feature_importance', {})),
                processing_time_ms=prediction.get('processing_time', 0.0) * 1000
            )
            db.add(prediction_record)
            db.commit()
            
        except Exception as e:
            logger.error(f"Error storing prediction: {e}")
    
    def _create_alert(self, packet: NetworkPacket, prediction: Dict[str, Any]):
        """Create security alert"""
        try:
            db = next(get_db())
            
            # Determine alert severity
            confidence = prediction.get('confidence', 0.0)
            if confidence >= 0.95:
                severity = 'CRITICAL'
            elif confidence >= 0.85:
                severity = 'HIGH'
            elif confidence >= 0.75:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Create alert message
            alert_message = (
                f"Anomaly detected from {packet.source_ip} to {packet.destination_ip} "
                f"using {packet.protocol} protocol. "
                f"Confidence: {confidence:.2%}, "
                f"Anomaly Score: {prediction.get('anomaly_score', 0.0):.3f}"
            )
            
            # Create alert record
            alert = Alert(
                prediction_id=None,  # Will be updated after prediction is stored
                severity=severity,
                alert_type=f"{packet.protocol}_ANOMALY",
                message=alert_message
            )
            db.add(alert)
            db.commit()
            
            # Call alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert, packet, prediction)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.warning(f"Security alert created: {alert_message}")
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    def add_anomaly_callback(self, callback: Callable[[NetworkPacket, Dict], None]):
        """Add callback for anomaly detection"""
        self.anomaly_callbacks.append(callback)
    
    def add_alert_callback(self, callback: Callable[[Any, NetworkPacket, Dict], None]):
        """Add callback for alert creation"""
        self.alert_callbacks.append(callback)
    
    def add_statistics_callback(self, callback: Callable[[Dict], None]):
        """Add callback for statistics updates"""
        self.statistics_callbacks.append(callback)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        
        # Calculate rates
        anomaly_rate = self.anomalies_detected / max(self.packets_processed, 1)
        processing_rate = self.packets_processed / max(uptime, 1)
        
        # Calculate average processing time
        avg_processing_time = statistics.mean(self.processing_times) if self.processing_times else 0
        
        return {
            'is_processing': self.is_processing,
            'uptime_seconds': uptime,
            'packets_processed': self.packets_processed,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_rate': anomaly_rate,
            'processing_rate_packets_per_second': processing_rate,
            'average_processing_time_ms': avg_processing_time * 1000,
            'batch_size': len(self.packet_batch),
            'model_loaded': self.model_service.is_loaded,
            'alert_thresholds': self.alert_thresholds
        }
    
    def update_alert_thresholds(self, thresholds: Dict[str, Any]):
        """Update alert thresholds"""
        self.alert_thresholds.update(thresholds)
        logger.info(f"Alert thresholds updated: {thresholds}")


# Global real-time processor instance
real_time_processor = RealTimeProcessor()


def get_real_time_processor() -> RealTimeProcessor:
    """Get real-time processor instance"""
    return real_time_processor 