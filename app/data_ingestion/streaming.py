import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import pandas as pd
from collections import deque
import time
from dataclasses import dataclass, asdict

from .validators import NetworkTrafficValidator, ValidationResult

@dataclass
class StreamRecord:
    """Record for streaming data"""
    data: Dict[str, Any]
    timestamp: datetime
    source: str
    batch_id: Optional[str] = None

class StreamingDataIngestion:
    """Real-time streaming data ingestion system"""
    
    def __init__(self, 
                 batch_size: int = 100,
                 batch_timeout: float = 5.0,
                 max_queue_size: int = 10000):
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.max_queue_size = max_queue_size
        
        # Queues for data processing
        self.input_queue = asyncio.Queue(maxsize=max_queue_size)
        self.validated_queue = asyncio.Queue(maxsize=max_queue_size)
        self.processing_queue = asyncio.Queue(maxsize=max_queue_size)
        
        # Data storage
        self.current_batch = deque()
        self.batch_counter = 0
        
        # Validator
        self.validator = NetworkTrafficValidator()
        
        # Callbacks
        self.on_batch_ready: Optional[Callable] = None
        self.on_validation_error: Optional[Callable] = None
        self.on_processing_error: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            'records_received': 0,
            'records_validated': 0,
            'records_processed': 0,
            'batches_created': 0,
            'validation_errors': 0,
            'processing_errors': 0
        }
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Control flags
        self.is_running = False
        self.tasks = []
    
    async def start(self):
        """Start the streaming ingestion system"""
        if self.is_running:
            return
        
        self.is_running = True
        self.logger.info("Starting streaming data ingestion system")
        
        # Start background tasks
        self.tasks = [
            asyncio.create_task(self._validation_worker()),
            asyncio.create_task(self._batch_processor()),
            asyncio.create_task(self._batch_timeout_handler())
        ]
        
        self.logger.info("Streaming ingestion system started")
    
    async def stop(self):
        """Stop the streaming ingestion system"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.logger.info("Stopping streaming data ingestion system")
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        self.logger.info("Streaming ingestion system stopped")
    
    async def ingest_record(self, data: Dict[str, Any], source: str = "unknown") -> bool:
        """Ingest a single record into the streaming pipeline"""
        if not self.is_running:
            self.logger.warning("Streaming system not running")
            return False
        
        try:
            record = StreamRecord(
                data=data,
                timestamp=datetime.now(),
                source=source
            )
            
            await self.input_queue.put(record)
            self.stats['records_received'] += 1
            return True
            
        except asyncio.QueueFull:
            self.logger.error("Input queue is full, dropping record")
            return False
        except Exception as e:
            self.logger.error(f"Error ingesting record: {e}")
            return False
    
    async def ingest_batch(self, records: List[Dict[str, Any]], source: str = "batch") -> bool:
        """Ingest a batch of records"""
        success_count = 0
        for record in records:
            success = await self.ingest_record(record, source)
            if success:
                success_count += 1
        
        self.logger.info(f"Ingested {success_count}/{len(records)} records from batch")
        return success_count == len(records)
    
    async def _validation_worker(self):
        """Background worker for data validation"""
        while self.is_running:
            try:
                # Get record from input queue
                record = await asyncio.wait_for(
                    self.input_queue.get(), 
                    timeout=1.0
                )
                
                # Validate record
                is_valid, errors = self.validator.validate_single_record(record.data)
                
                if is_valid:
                    await self.validated_queue.put(record)
                    self.stats['records_validated'] += 1
                else:
                    self.stats['validation_errors'] += 1
                    if self.on_validation_error:
                        await self.on_validation_error(record, errors)
                    else:
                        self.logger.warning(f"Validation errors for record: {errors}")
                
                self.input_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in validation worker: {e}")
    
    async def _batch_processor(self):
        """Background worker for batch processing"""
        while self.is_running:
            try:
                # Get validated record
                record = await asyncio.wait_for(
                    self.validated_queue.get(),
                    timeout=1.0
                )
                
                # Add to current batch
                self.current_batch.append(record)
                
                # Check if batch is ready
                if len(self.current_batch) >= self.batch_size:
                    await self._process_batch()
                
                self.validated_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in batch processor: {e}")
    
    async def _batch_timeout_handler(self):
        """Handle batch timeouts"""
        while self.is_running:
            try:
                await asyncio.sleep(self.batch_timeout)
                
                # Process batch if it has records and timeout reached
                if len(self.current_batch) > 0:
                    await self._process_batch()
                    
            except Exception as e:
                self.logger.error(f"Error in batch timeout handler: {e}")
    
    async def _process_batch(self):
        """Process the current batch"""
        if not self.current_batch:
            return
        
        batch_id = f"batch_{self.batch_counter}_{int(time.time())}"
        self.batch_counter += 1
        
        # Create batch DataFrame
        batch_data = []
        for record in self.current_batch:
            record.batch_id = batch_id
            batch_data.append(record.data)
        
        df = pd.DataFrame(batch_data)
        
        # Validate entire batch
        validation_result = self.validator.validate_dataframe(df)
        
        if validation_result.is_valid:
            # Send to processing queue
            batch_record = StreamRecord(
                data={'batch_id': batch_id, 'dataframe': df, 'validation_result': validation_result},
                timestamp=datetime.now(),
                source='batch_processor',
                batch_id=batch_id
            )
            
            await self.processing_queue.put(batch_record)
            self.stats['batches_created'] += 1
            self.stats['records_processed'] += len(df)
            
            # Call callback if provided
            if self.on_batch_ready:
                await self.on_batch_ready(batch_record)
            
            self.logger.info(f"Processed batch {batch_id} with {len(df)} records")
        else:
            self.stats['processing_errors'] += 1
            self.logger.error(f"Batch {batch_id} validation failed: {validation_result.errors}")
            
            if self.on_processing_error:
                await self.on_processing_error(batch_record, validation_result.errors)
        
        # Clear current batch
        self.current_batch.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            **self.stats,
            'queue_sizes': {
                'input': self.input_queue.qsize(),
                'validated': self.validated_queue.qsize(),
                'processing': self.processing_queue.qsize()
            },
            'current_batch_size': len(self.current_batch),
            'is_running': self.is_running
        }
    
    async def get_processing_queue(self) -> asyncio.Queue:
        """Get the processing queue for downstream consumers"""
        return self.processing_queue

class KafkaStreamingIngestion(StreamingDataIngestion):
    """Kafka-based streaming ingestion"""
    
    def __init__(self, kafka_config: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.kafka_config = kafka_config
        self.kafka_consumer = None
        self.kafka_producer = None
    
    async def start(self):
        """Start Kafka streaming ingestion"""
        # Initialize Kafka consumer/producer here
        # This is a placeholder - you would need to implement actual Kafka integration
        await super().start()
    
    async def consume_from_topic(self, topic: str):
        """Consume records from Kafka topic"""
        # Placeholder for Kafka consumer implementation
        pass
    
    async def produce_to_topic(self, topic: str, data: Dict[str, Any]):
        """Produce records to Kafka topic"""
        # Placeholder for Kafka producer implementation
        pass 