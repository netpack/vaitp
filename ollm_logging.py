"""
oLLM-specific logging and monitoring infrastructure.

This module provides comprehensive logging and monitoring capabilities for oLLM operations,
including backend selection, model loading, inference operations, and resource usage tracking.
"""

import logging
import time
import json
import psutil
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from pathlib import Path


@dataclass
class OLLMResourceSnapshot:
    """Snapshot of system resources during oLLM operations."""
    timestamp: str
    memory_usage_mb: float
    memory_percent: float
    cpu_percent: float
    gpu_memory_mb: Optional[float] = None
    ssd_read_mb: Optional[float] = None
    ssd_write_mb: Optional[float] = None
    process_memory_mb: Optional[float] = None


@dataclass
class OLLMBackendSelectionLog:
    """Log entry for oLLM backend selection decisions."""
    timestamp: str
    model_name: str
    model_size_gb: float
    available_vram_gb: float
    available_ssd_gb: float
    backend_selected: str
    selection_reason: str
    forced_backend: Optional[str] = None
    fallback_occurred: bool = False
    selection_time_ms: float = 0.0


@dataclass
class OLLMModelLoadingLog:
    """Log entry for oLLM model loading operations."""
    timestamp: str
    model_name: str
    model_path: str
    backend_type: str
    config: Dict[str, Any]
    success: bool
    loading_time_ms: float
    error_message: Optional[str] = None
    memory_before_mb: Optional[float] = None
    memory_after_mb: Optional[float] = None
    memory_delta_mb: Optional[float] = None
    device: Optional[str] = None


@dataclass
class OLLMInferenceLog:
    """Log entry for oLLM inference operations."""
    timestamp: str
    model_name: str
    backend_type: str
    prompt_length: int
    generated_length: int
    inference_time_ms: float
    tokens_per_second: float
    memory_peak_mb: Optional[float] = None
    ssd_io_mb: Optional[float] = None
    parameters: Dict[str, Any] = None
    error_message: Optional[str] = None


@dataclass
class OLLMPerformanceMetrics:
    """Performance metrics for oLLM operations."""
    session_id: str
    model_name: str
    backend_type: str
    total_inferences: int
    total_tokens_generated: int
    average_tokens_per_second: float
    total_inference_time_ms: float
    peak_memory_usage_mb: float
    total_ssd_io_mb: float
    session_start: str
    session_end: str


class OLLMResourceMonitor:
    """Real-time resource monitoring for oLLM operations."""
    
    def __init__(self, monitoring_interval: float = 0.5):
        """
        Initialize the resource monitor.
        
        Args:
            monitoring_interval: Interval between resource snapshots in seconds
        """
        self.monitoring_interval = monitoring_interval
        self.monitoring = False
        self.monitor_thread = None
        self.snapshots: List[OLLMResourceSnapshot] = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger(f"{__name__}.OLLMResourceMonitor")
        
        # Initialize baseline metrics
        self.baseline_io = self._get_io_stats()
    
    def __enter__(self):
        """Context manager entry."""
        self.start_monitoring()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_monitoring()
        return False
    
    def _get_io_stats(self) -> Optional[Dict[str, float]]:
        """Get current I/O statistics."""
        try:
            io_stats = psutil.disk_io_counters()
            if io_stats:
                return {
                    'read_bytes': io_stats.read_bytes,
                    'write_bytes': io_stats.write_bytes
                }
        except Exception as e:
            self.logger.debug(f"Failed to get I/O stats: {e}")
        return None
    
    def _get_gpu_memory(self) -> Optional[float]:
        """Get GPU memory usage in MB."""
        try:
            import torch
            if torch.cuda.is_available():
                return torch.cuda.memory_allocated() / (1024 * 1024)
            elif torch.backends.mps.is_available():
                # MPS doesn't provide direct memory usage, estimate
                return None
        except ImportError:
            pass
        return None
    
    def _take_snapshot(self) -> OLLMResourceSnapshot:
        """Take a snapshot of current system resources."""
        memory = psutil.virtual_memory()
        process = psutil.Process()
        
        # Calculate SSD I/O delta
        current_io = self._get_io_stats()
        ssd_read_mb = None
        ssd_write_mb = None
        
        if current_io and self.baseline_io:
            read_delta = current_io['read_bytes'] - self.baseline_io['read_bytes']
            write_delta = current_io['write_bytes'] - self.baseline_io['write_bytes']
            ssd_read_mb = read_delta / (1024 * 1024)
            ssd_write_mb = write_delta / (1024 * 1024)
        
        return OLLMResourceSnapshot(
            timestamp=datetime.now().isoformat(),
            memory_usage_mb=memory.used / (1024 * 1024),
            memory_percent=memory.percent,
            cpu_percent=psutil.cpu_percent(),
            gpu_memory_mb=self._get_gpu_memory(),
            ssd_read_mb=ssd_read_mb,
            ssd_write_mb=ssd_write_mb,
            process_memory_mb=process.memory_info().rss / (1024 * 1024)
        )
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                snapshot = self._take_snapshot()
                with self.lock:
                    self.snapshots.append(snapshot)
                    # Keep only last 1000 snapshots to prevent memory bloat
                    if len(self.snapshots) > 1000:
                        self.snapshots = self.snapshots[-1000:]
                
                time.sleep(self.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)
    
    def start_monitoring(self):
        """Start resource monitoring."""
        if not self.monitoring:
            self.monitoring = True
            self.snapshots.clear()
            self.baseline_io = self._get_io_stats()
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.debug("Started resource monitoring")
    
    def stop_monitoring(self) -> List[OLLMResourceSnapshot]:
        """
        Stop resource monitoring and return collected snapshots.
        
        Returns:
            List of resource snapshots collected during monitoring
        """
        if self.monitoring:
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2.0)
            
            with self.lock:
                snapshots = self.snapshots.copy()
                self.snapshots.clear()
            
            self.logger.debug(f"Stopped resource monitoring, collected {len(snapshots)} snapshots")
            return snapshots
        return []
    
    def get_peak_usage(self) -> Dict[str, float]:
        """Get peak resource usage from collected snapshots."""
        if not self.snapshots:
            return {}
        
        with self.lock:
            snapshots = self.snapshots.copy()
        
        peak_memory = max(s.memory_usage_mb for s in snapshots)
        peak_cpu = max(s.cpu_percent for s in snapshots)
        peak_process_memory = max(s.process_memory_mb for s in snapshots if s.process_memory_mb)
        
        peak_gpu = None
        if any(s.gpu_memory_mb for s in snapshots):
            peak_gpu = max(s.gpu_memory_mb for s in snapshots if s.gpu_memory_mb)
        
        total_ssd_read = sum(s.ssd_read_mb for s in snapshots if s.ssd_read_mb) or 0
        total_ssd_write = sum(s.ssd_write_mb for s in snapshots if s.ssd_write_mb) or 0
        
        return {
            'peak_memory_mb': peak_memory,
            'peak_cpu_percent': peak_cpu,
            'peak_process_memory_mb': peak_process_memory,
            'peak_gpu_memory_mb': peak_gpu,
            'total_ssd_read_mb': total_ssd_read,
            'total_ssd_write_mb': total_ssd_write
        }


class OLLMLogger:
    """Centralized logger for oLLM operations."""
    
    def __init__(self, log_level: int = logging.INFO):
        """
        Initialize the oLLM logger.
        
        Args:
            log_level: Logging level for oLLM operations
        """
        self.logger = logging.getLogger("ollm_operations")
        self.logger.setLevel(log_level)
        
        # Create structured formatter for oLLM logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [oLLM] %(message)s'
        )
        
        # Add handler if not already present
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # Storage for structured logs
        self.backend_selection_logs: List[OLLMBackendSelectionLog] = []
        self.model_loading_logs: List[OLLMModelLoadingLog] = []
        self.inference_logs: List[OLLMInferenceLog] = []
        
        # Resource monitor
        self.resource_monitor = OLLMResourceMonitor()
    
    def log_backend_selection(self, 
                            model_name: str,
                            model_size_gb: float,
                            available_vram_gb: float,
                            available_ssd_gb: float,
                            backend_selected: str,
                            selection_reason: str,
                            forced_backend: Optional[str] = None,
                            fallback_occurred: bool = False,
                            selection_time_ms: float = 0.0):
        """
        Log backend selection decision.
        
        Args:
            model_name: Name of the model
            model_size_gb: Size of the model in GB
            available_vram_gb: Available VRAM in GB
            available_ssd_gb: Available SSD space in GB
            backend_selected: Selected backend ("ollm" or "llamacpp")
            selection_reason: Reason for backend selection
            forced_backend: If backend was forced by user
            fallback_occurred: Whether fallback from oLLM to llamacpp occurred
            selection_time_ms: Time taken for selection in milliseconds
        """
        log_entry = OLLMBackendSelectionLog(
            timestamp=datetime.now().isoformat(),
            model_name=model_name,
            model_size_gb=model_size_gb,
            available_vram_gb=available_vram_gb,
            available_ssd_gb=available_ssd_gb,
            backend_selected=backend_selected,
            selection_reason=selection_reason,
            forced_backend=forced_backend,
            fallback_occurred=fallback_occurred,
            selection_time_ms=selection_time_ms
        )
        
        self.backend_selection_logs.append(log_entry)
        
        # Log to standard logger
        level = logging.WARNING if fallback_occurred else logging.INFO
        self.logger.log(level, 
            f"Backend Selection: {backend_selected} for {model_name} "
            f"({model_size_gb:.1f}GB) - {selection_reason}"
        )
        
        if forced_backend:
            self.logger.info(f"Backend forced to: {forced_backend}")
        
        if fallback_occurred:
            self.logger.warning(f"Fallback occurred from oLLM to llamacpp")
    
    def log_model_loading(self,
                         model_name: str,
                         model_path: str,
                         backend_type: str,
                         config: Dict[str, Any],
                         success: bool,
                         loading_time_ms: float,
                         error_message: Optional[str] = None,
                         memory_before_mb: Optional[float] = None,
                         memory_after_mb: Optional[float] = None,
                         device: Optional[str] = None):
        """
        Log model loading operation.
        
        Args:
            model_name: Name of the model
            model_path: Path to the model file
            backend_type: Type of backend used
            config: Configuration used for loading
            success: Whether loading was successful
            loading_time_ms: Time taken for loading in milliseconds
            error_message: Error message if loading failed
            memory_before_mb: Memory usage before loading
            memory_after_mb: Memory usage after loading
            device: Device used for loading
        """
        memory_delta_mb = None
        if memory_before_mb is not None and memory_after_mb is not None:
            memory_delta_mb = memory_after_mb - memory_before_mb
        
        log_entry = OLLMModelLoadingLog(
            timestamp=datetime.now().isoformat(),
            model_name=model_name,
            model_path=model_path,
            backend_type=backend_type,
            config=config,
            success=success,
            loading_time_ms=loading_time_ms,
            error_message=error_message,
            memory_before_mb=memory_before_mb,
            memory_after_mb=memory_after_mb,
            memory_delta_mb=memory_delta_mb,
            device=device
        )
        
        self.model_loading_logs.append(log_entry)
        
        # Log to standard logger
        if success:
            self.logger.info(
                f"Model Loading SUCCESS: {model_name} ({backend_type}) "
                f"in {loading_time_ms:.1f}ms"
            )
            if memory_delta_mb:
                self.logger.info(f"Memory usage increased by {memory_delta_mb:.1f}MB")
        else:
            self.logger.error(
                f"Model Loading FAILED: {model_name} ({backend_type}) - {error_message}"
            )
    
    def log_inference_operation(self,
                              model_name: str,
                              backend_type: str,
                              prompt_length: int,
                              generated_length: int,
                              inference_time_ms: float,
                              parameters: Dict[str, Any],
                              memory_peak_mb: Optional[float] = None,
                              ssd_io_mb: Optional[float] = None,
                              error_message: Optional[str] = None):
        """
        Log inference operation.
        
        Args:
            model_name: Name of the model
            backend_type: Type of backend used
            prompt_length: Length of input prompt in characters
            generated_length: Length of generated text in characters
            inference_time_ms: Time taken for inference in milliseconds
            parameters: Inference parameters used
            memory_peak_mb: Peak memory usage during inference
            ssd_io_mb: SSD I/O during inference
            error_message: Error message if inference failed
        """
        # Calculate tokens per second (rough approximation)
        tokens_per_second = 0.0
        if inference_time_ms > 0 and generated_length > 0:
            # Rough approximation: 4 characters per token
            estimated_tokens = generated_length / 4
            tokens_per_second = (estimated_tokens * 1000) / inference_time_ms
        
        log_entry = OLLMInferenceLog(
            timestamp=datetime.now().isoformat(),
            model_name=model_name,
            backend_type=backend_type,
            prompt_length=prompt_length,
            generated_length=generated_length,
            inference_time_ms=inference_time_ms,
            tokens_per_second=tokens_per_second,
            memory_peak_mb=memory_peak_mb,
            ssd_io_mb=ssd_io_mb,
            parameters=parameters,
            error_message=error_message
        )
        
        self.inference_logs.append(log_entry)
        
        # Log to standard logger
        if error_message:
            self.logger.error(
                f"Inference FAILED: {model_name} ({backend_type}) - {error_message}"
            )
        else:
            self.logger.info(
                f"Inference: {model_name} ({backend_type}) "
                f"{generated_length} chars in {inference_time_ms:.1f}ms "
                f"({tokens_per_second:.1f} tok/s)"
            )
    
    @contextmanager
    def monitor_operation(self, operation_name: str):
        """
        Context manager for monitoring resource usage during operations.
        
        Args:
            operation_name: Name of the operation being monitored
        """
        self.logger.debug(f"Starting resource monitoring for: {operation_name}")
        self.resource_monitor.start_monitoring()
        
        try:
            yield self.resource_monitor
        finally:
            snapshots = self.resource_monitor.stop_monitoring()
            peak_usage = self.resource_monitor.get_peak_usage()
            
            self.logger.debug(
                f"Operation '{operation_name}' completed. "
                f"Peak memory: {peak_usage.get('peak_memory_mb', 0):.1f}MB, "
                f"Peak CPU: {peak_usage.get('peak_cpu_percent', 0):.1f}%"
            )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get performance summary of all logged operations.
        
        Returns:
            Dictionary containing performance metrics summary
        """
        summary = {
            'backend_selections': len(self.backend_selection_logs),
            'model_loadings': len(self.model_loading_logs),
            'inferences': len(self.inference_logs),
            'successful_loadings': sum(1 for log in self.model_loading_logs if log.success),
            'failed_loadings': sum(1 for log in self.model_loading_logs if not log.success),
            'ollm_selections': sum(1 for log in self.backend_selection_logs 
                                 if log.backend_selected == 'ollm'),
            'llamacpp_selections': sum(1 for log in self.backend_selection_logs 
                                     if log.backend_selected == 'llamacpp'),
            'fallback_occurrences': sum(1 for log in self.backend_selection_logs 
                                      if log.fallback_occurred)
        }
        
        # Calculate average inference performance
        if self.inference_logs:
            successful_inferences = [log for log in self.inference_logs if not log.error_message]
            if successful_inferences:
                avg_tokens_per_second = sum(log.tokens_per_second for log in successful_inferences) / len(successful_inferences)
                avg_inference_time = sum(log.inference_time_ms for log in successful_inferences) / len(successful_inferences)
                
                summary.update({
                    'average_tokens_per_second': avg_tokens_per_second,
                    'average_inference_time_ms': avg_inference_time,
                    'successful_inferences': len(successful_inferences),
                    'failed_inferences': len(self.inference_logs) - len(successful_inferences)
                })
        
        return summary
    
    def export_logs(self, filepath: str):
        """
        Export all logs to a JSON file.
        
        Args:
            filepath: Path to export the logs to
        """
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'backend_selection_logs': [asdict(log) for log in self.backend_selection_logs],
            'model_loading_logs': [asdict(log) for log in self.model_loading_logs],
            'inference_logs': [asdict(log) for log in self.inference_logs],
            'performance_summary': self.get_performance_summary()
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Exported oLLM logs to: {filepath}")
    
    def clear_logs(self):
        """Clear all stored logs."""
        self.backend_selection_logs.clear()
        self.model_loading_logs.clear()
        self.inference_logs.clear()
        self.logger.info("Cleared all oLLM logs")


# Global oLLM logger instance
_ollm_logger = None

def get_ollm_logger() -> OLLMLogger:
    """Get the global oLLM logger instance."""
    global _ollm_logger
    if _ollm_logger is None:
        _ollm_logger = OLLMLogger()
    return _ollm_logger


def configure_ollm_logging(log_level: int = logging.INFO, 
                          log_file: Optional[str] = None):
    """
    Configure oLLM logging settings.
    
    Args:
        log_level: Logging level for oLLM operations
        log_file: Optional file to write oLLM logs to
    """
    global _ollm_logger
    _ollm_logger = OLLMLogger(log_level)
    
    if log_file:
        # Add file handler for oLLM logs
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [oLLM] %(message)s'
        )
        file_handler.setFormatter(formatter)
        _ollm_logger.logger.addHandler(file_handler)
        _ollm_logger.logger.info(f"oLLM logging configured, writing to: {log_file}")