import pandas as pd
import numpy as np
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Generator
from datetime import datetime, timedelta
import os
import json
from pathlib import Path
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import gc

from .validators import NetworkTrafficValidator, ValidationResult, DataQualityMonitor

class BatchDataProcessor:
    """Batch data processing system for large datasets"""
    
    def __init__(self, 
                 chunk_size: int = 10000,
                 max_workers: int = None,
                 output_dir: str = "processed_data"):
        self.chunk_size = chunk_size
        self.max_workers = max_workers or min(mp.cpu_count(), 4)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Validator and quality monitor
        self.validator = NetworkTrafficValidator()
        self.quality_monitor = DataQualityMonitor()
        
        # Statistics
        self.stats = {
            'files_processed': 0,
            'chunks_processed': 0,
            'records_processed': 0,
            'validation_errors': 0,
            'processing_errors': 0,
            'processing_time': 0
        }
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Callbacks
        self.on_chunk_processed: Optional[Callable] = None
        self.on_file_processed: Optional[Callable] = None
        self.on_validation_error: Optional[Callable] = None
    
    def process_file(self, file_path: str, output_format: str = "parquet") -> Dict[str, Any]:
        """Process a single file in chunks"""
        start_time = datetime.now()
        self.logger.info(f"Starting to process file: {file_path}")
        
        try:
            # Read file in chunks
            chunks = self._read_file_chunks(file_path)
            
            processed_chunks = []
            validation_results = []
            
            for chunk_idx, chunk in enumerate(chunks):
                self.logger.info(f"Processing chunk {chunk_idx + 1}")
                
                # Validate chunk
                validation_result = self.validator.validate_dataframe(chunk)
                validation_results.append(validation_result)
                
                # Record quality metrics
                self.quality_monitor.record_validation(validation_result)
                
                if validation_result.is_valid:
                    # Process valid chunk
                    processed_chunk = self._process_chunk(chunk)
                    processed_chunks.append(processed_chunk)
                    
                    self.stats['chunks_processed'] += 1
                    self.stats['records_processed'] += len(chunk)
                    
                    # Call callback
                    if self.on_chunk_processed:
                        self.on_chunk_processed(processed_chunk, validation_result)
                else:
                    self.stats['validation_errors'] += 1
                    self.logger.warning(f"Chunk {chunk_idx + 1} validation failed: {validation_result.errors}")
                    
                    if self.on_validation_error:
                        self.on_validation_error(chunk, validation_result)
            
            # Combine processed chunks
            if processed_chunks:
                final_data = pd.concat(processed_chunks, ignore_index=True)
                
                # Save processed data
                output_path = self._save_processed_data(final_data, file_path, output_format)
                
                # Update statistics
                processing_time = (datetime.now() - start_time).total_seconds()
                self.stats['files_processed'] += 1
                self.stats['processing_time'] += processing_time
                
                # Call callback
                if self.on_file_processed:
                    self.on_file_processed(output_path, final_data)
                
                self.logger.info(f"File processed successfully: {output_path}")
                
                return {
                    'success': True,
                    'output_path': str(output_path),
                    'records_processed': len(final_data),
                    'processing_time': processing_time,
                    'validation_results': validation_results
                }
            else:
                self.logger.error("No valid chunks found in file")
                return {
                    'success': False,
                    'error': 'No valid chunks found'
                }
                
        except Exception as e:
            self.stats['processing_errors'] += 1
            self.logger.error(f"Error processing file {file_path}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_directory(self, directory_path: str, file_pattern: str = "*.csv") -> List[Dict[str, Any]]:
        """Process all files in a directory"""
        directory = Path(directory_path)
        files = list(directory.glob(file_pattern))
        
        self.logger.info(f"Found {len(files)} files to process in {directory_path}")
        
        results = []
        for file_path in files:
            result = self.process_file(str(file_path))
            results.append(result)
        
        return results
    
    async def process_file_async(self, file_path: str, output_format: str = "parquet") -> Dict[str, Any]:
        """Process a file asynchronously"""
        loop = asyncio.get_event_loop()
        
        # Run in thread pool to avoid blocking
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            result = await loop.run_in_executor(
                executor, 
                self.process_file, 
                file_path, 
                output_format
            )
        
        return result
    
    async def process_directory_async(self, directory_path: str, file_pattern: str = "*.csv") -> List[Dict[str, Any]]:
        """Process all files in a directory asynchronously"""
        directory = Path(directory_path)
        files = list(directory.glob(file_pattern))
        
        self.logger.info(f"Processing {len(files)} files asynchronously")
        
        # Process files concurrently
        tasks = [
            self.process_file_async(str(file_path)) 
            for file_path in files
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Error processing file {files[i]}: {result}")
                processed_results.append({
                    'success': False,
                    'error': str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    def _read_file_chunks(self, file_path: str) -> Generator[pd.DataFrame, None, None]:
        """Read file in chunks"""
        file_extension = Path(file_path).suffix.lower()
        
        if file_extension == '.csv':
            for chunk in pd.read_csv(file_path, chunksize=self.chunk_size):
                yield chunk
        elif file_extension == '.parquet':
            # For parquet files, read in chunks using pyarrow
            try:
                import pyarrow.parquet as pq
                parquet_file = pq.ParquetFile(file_path)
                
                for batch in parquet_file.iter_batches(batch_size=self.chunk_size):
                    yield batch.to_pandas()
            except ImportError:
                # Fallback to pandas
                df = pd.read_parquet(file_path)
                for i in range(0, len(df), self.chunk_size):
                    yield df.iloc[i:i + self.chunk_size]
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")
    
    def _process_chunk(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """Process a single chunk of data"""
        # Add processing timestamp
        chunk['processed_at'] = datetime.now()
        
        # Add any additional processing here
        # For example, feature engineering, data cleaning, etc.
        
        return chunk
    
    def _save_processed_data(self, data: pd.DataFrame, original_file: str, format: str) -> Path:
        """Save processed data to file"""
        original_name = Path(original_file).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == 'parquet':
            output_path = self.output_dir / f"{original_name}_processed_{timestamp}.parquet"
            data.to_parquet(output_path, index=False)
        elif format.lower() == 'csv':
            output_path = self.output_dir / f"{original_name}_processed_{timestamp}.csv"
            data.to_csv(output_path, index=False)
        elif format.lower() == 'json':
            output_path = self.output_dir / f"{original_name}_processed_{timestamp}.json"
            data.to_json(output_path, orient='records', indent=2)
        else:
            raise ValueError(f"Unsupported output format: {format}")
        
        return output_path
    
    def get_quality_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get data quality report"""
        return {
            'quality_summary': self.quality_monitor.get_quality_summary(hours),
            'processing_stats': self.stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def reset_stats(self):
        """Reset processing statistics"""
        self.stats = {
            'files_processed': 0,
            'chunks_processed': 0,
            'records_processed': 0,
            'validation_errors': 0,
            'processing_errors': 0,
            'processing_time': 0
        }

class DataPipeline:
    """Complete data processing pipeline"""
    
    def __init__(self, 
                 input_dir: str = "input_data",
                 output_dir: str = "processed_data",
                 temp_dir: str = "temp_data"):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.temp_dir = Path(temp_dir)
        
        # Create directories
        for directory in [self.input_dir, self.output_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True)
        
        # Initialize processors
        self.batch_processor = BatchDataProcessor(output_dir=str(self.output_dir))
        self.streaming_processor = None  # Will be initialized when needed
        
        # Pipeline configuration
        self.config = {
            'enable_streaming': False,
            'enable_batch_processing': True,
            'enable_quality_monitoring': True,
            'auto_cleanup_temp': True,
            'retention_days': 7
        }
        
        self.logger = logging.getLogger(__name__)
    
    async def run_pipeline(self, 
                          input_files: List[str] = None,
                          streaming_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the complete data pipeline"""
        start_time = datetime.now()
        results = {
            'batch_processing': {},
            'streaming_processing': {},
            'quality_report': {},
            'pipeline_time': 0
        }
        
        try:
            # Batch processing
            if self.config['enable_batch_processing']:
                if input_files:
                    results['batch_processing'] = await self.batch_processor.process_directory_async(
                        str(self.input_dir)
                    )
                else:
                    results['batch_processing'] = await self.batch_processor.process_directory_async(
                        str(self.input_dir)
                    )
            
            # Streaming processing
            if self.config['enable_streaming'] and streaming_config:
                results['streaming_processing'] = await self._run_streaming_pipeline(streaming_config)
            
            # Quality report
            if self.config['enable_quality_monitoring']:
                results['quality_report'] = self.batch_processor.get_quality_report()
            
            # Cleanup
            if self.config['auto_cleanup_temp']:
                self._cleanup_temp_files()
            
            results['pipeline_time'] = (datetime.now() - start_time).total_seconds()
            
            self.logger.info(f"Pipeline completed in {results['pipeline_time']:.2f} seconds")
            
        except Exception as e:
            self.logger.error(f"Pipeline error: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _run_streaming_pipeline(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run streaming pipeline"""
        # Placeholder for streaming pipeline implementation
        return {'status': 'streaming_not_implemented'}
    
    def _cleanup_temp_files(self):
        """Clean up temporary files older than retention period"""
        cutoff_time = datetime.now() - timedelta(days=self.config['retention_days'])
        
        for file_path in self.temp_dir.rglob("*"):
            if file_path.is_file():
                file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_time < cutoff_time:
                    file_path.unlink()
                    self.logger.info(f"Cleaned up old file: {file_path}")
    
    def update_config(self, new_config: Dict[str, Any]):
        """Update pipeline configuration"""
        self.config.update(new_config)
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status"""
        return {
            'config': self.config,
            'directories': {
                'input': str(self.input_dir),
                'output': str(self.output_dir),
                'temp': str(self.temp_dir)
            },
            'batch_processor_stats': self.batch_processor.stats,
            'quality_summary': self.batch_processor.get_quality_report()
        } 