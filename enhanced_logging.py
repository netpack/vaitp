"""
Enhanced Logging System for VAITP Platform

This module provides structured logging with GPU assignments, process status,
and detailed debugging information for parallel execution monitoring.

Requirements implemented:
- 3.4, 3.5: Detailed logging for GPU assignments and process status
- 4.5: Enhanced debugging capabilities and system resource monitoring
"""

import logging
import json
import time
import os
import sys
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass, asdict
import traceback

@dataclass
class LogContext:
    """Context information for structured logging."""
    model_name: Optional[str] = None
    process_id: Optional[int] = None
    gpu_id: Optional[int] = None
    task_name: Optional[str] = None
    execution_phase: Optional[str] = None
    timestamp: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON logging."""
        return {k: v for k, v in asdict(self).items() if v is not None}

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging with JSON output."""
    
    def __init__(self, include_context: bool = True):
        """
        Initialize structured formatter.
        
        Args:
            include_context: Whether to include context information in logs
        """
        super().__init__()
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with structured information."""
        # Base log data
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add context if available
        if self.include_context and hasattr(record, 'context'):
            log_data['context'] = record.context.to_dict()
        
        # Add exception information
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 
                          'exc_text', 'stack_info', 'context']:
                log_data['extra'] = log_data.get('extra', {})
                log_data['extra'][key] = value
        
        return json.dumps(log_data, default=str)

class ContextualLogger:
    """Logger with contextual information for parallel execution tracking."""
    
    def __init__(self, name: str, context: Optional[LogContext] = None):
        """
        Initialize contextual logger.
        
        Args:
            name: Logger name
            context: Default context for this logger
        """
        self.logger = logging.getLogger(name)
        self.default_context = context or LogContext()
        self._local = threading.local()
    
    def set_context(self, **kwargs) -> None:
        """Set context for current thread."""
        if not hasattr(self._local, 'context'):
            self._local.context = LogContext()
        
        for key, value in kwargs.items():
            if hasattr(self._local.context, key):
                setattr(self._local.context, key, value)
    
    def get_context(self) -> LogContext:
        """Get current context, merging thread-local with default."""
        thread_context = getattr(self._local, 'context', LogContext())
        
        # Merge contexts (thread-local takes precedence)
        merged = LogContext()
        for field in ['model_name', 'process_id', 'gpu_id', 'task_name', 'execution_phase', 'timestamp']:
            thread_value = getattr(thread_context, field, None)
            default_value = getattr(self.default_context, field, None)
            setattr(merged, field, thread_value if thread_value is not None else default_value)
        
        # Always set current timestamp if not provided
        if merged.timestamp is None:
            merged.timestamp = time.time()
        
        return merged
    
    def _log_with_context(self, level: int, message: str, *args, **kwargs) -> None:
        """Log message with context information."""
        context = self.get_context()
        
        # Create log record
        record = self.logger.makeRecord(
            self.logger.name, level, '', 0, message, args, None
        )
        record.context = context
        
        # Add any extra kwargs
        for key, value in kwargs.items():
            setattr(record, key, value)
        
        self.logger.handle(record)
    
    def debug(self, message: str, *args, **kwargs) -> None:
        """Log debug message with context."""
        self._log_with_context(logging.DEBUG, message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs) -> None:
        """Log info message with context."""
        self._log_with_context(logging.INFO, message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs) -> None:
        """Log warning message with context."""
        self._log_with_context(logging.WARNING, message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs) -> None:
        """Log error message with context."""
        self._log_with_context(logging.ERROR, message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs) -> None:
        """Log critical message with context."""
        self._log_with_context(logging.CRITICAL, message, *args, **kwargs)
    
    def log_gpu_assignment(self, model_name: str, gpu_id: int, process_id: int) -> None:
        """Log GPU assignment with structured information."""
        self.info(
            f"GPU assignment: {model_name} -> GPU {gpu_id}",
            gpu_assignment=True,
            model_name=model_name,
            gpu_id=gpu_id,
            process_id=process_id
        )
    
    def log_process_start(self, model_name: str, process_id: int, gpu_id: int, total_tasks: int) -> None:
        """Log process start with detailed information."""
        self.info(
            f"Process started: {model_name} (PID: {process_id}, GPU: {gpu_id}, Tasks: {total_tasks})",
            process_event='start',
            model_name=model_name,
            process_id=process_id,
            gpu_id=gpu_id,
            total_tasks=total_tasks
        )
    
    def log_process_progress(self, model_name: str, completed_tasks: int, total_tasks: int, current_task: str) -> None:
        """Log process progress update."""
        progress_percent = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        self.info(
            f"Progress update: {model_name} - {completed_tasks}/{total_tasks} ({progress_percent:.1f}%) - {current_task}",
            process_event='progress',
            model_name=model_name,
            completed_tasks=completed_tasks,
            total_tasks=total_tasks,
            progress_percent=progress_percent,
            current_task=current_task
        )
    
    def log_process_completion(self, model_name: str, process_id: int, duration: float, success: bool, error: Optional[str] = None) -> None:
        """Log process completion with results."""
        status = 'completed' if success else 'failed'
        message = f"Process {status}: {model_name} (PID: {process_id}, Duration: {duration:.2f}s)"
        
        if success:
            self.info(
                message,
                process_event='completion',
                model_name=model_name,
                process_id=process_id,
                duration=duration,
                success=True
            )
        else:
            self.error(
                f"{message} - Error: {error}",
                process_event='completion',
                model_name=model_name,
                process_id=process_id,
                duration=duration,
                success=False,
                error_message=error
            )
    
    def log_resource_usage(self, gpu_info: List[Dict[str, Any]], system_info: Dict[str, Any]) -> None:
        """Log current resource usage."""
        self.info(
            "Resource usage snapshot",
            resource_monitoring=True,
            gpu_info=gpu_info,
            system_info=system_info
        )
    
    def log_performance_alert(self, alert_type: str, message: str, severity: str, **kwargs) -> None:
        """Log performance alert."""
        log_method = getattr(self, severity.lower(), self.warning)
        log_method(
            f"Performance Alert [{alert_type}]: {message}",
            alert=True,
            alert_type=alert_type,
            severity=severity,
            **kwargs
        )

class LoggingManager:
    """Centralized logging management for the VAITP platform."""
    
    def __init__(self, log_dir: str = "logs", max_file_size: int = 100*1024*1024, backup_count: int = 5):
        """
        Initialize logging manager.
        
        Args:
            log_dir: Directory for log files
            max_file_size: Maximum size per log file in bytes
            backup_count: Number of backup files to keep
        """
        self.log_dir = log_dir
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure root logger
        self._setup_root_logger()
        
        # Create specialized loggers
        self.execution_logger = self._create_execution_logger()
        self.performance_logger = self._create_performance_logger()
        self.debug_logger = self._create_debug_logger()
        
        # Contextual loggers
        self._contextual_loggers: Dict[str, ContextualLogger] = {}
    
    def _setup_root_logger(self) -> None:
        """Setup root logger configuration."""
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        
        # Console handler with simple format
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    def _create_execution_logger(self) -> logging.Logger:
        """Create logger for execution events."""
        logger = logging.getLogger('vaitp.execution')
        logger.setLevel(logging.INFO)
        
        # File handler with structured format
        handler = RotatingFileHandler(
            os.path.join(self.log_dir, 'execution.jsonl'),
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        handler.setFormatter(StructuredFormatter(include_context=True))
        logger.addHandler(handler)
        
        return logger
    
    def _create_performance_logger(self) -> logging.Logger:
        """Create logger for performance monitoring."""
        logger = logging.getLogger('vaitp.performance')
        logger.setLevel(logging.INFO)
        
        # File handler for performance data
        handler = RotatingFileHandler(
            os.path.join(self.log_dir, 'performance.jsonl'),
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        handler.setFormatter(StructuredFormatter(include_context=False))
        logger.addHandler(handler)
        
        return logger
    
    def _create_debug_logger(self) -> logging.Logger:
        """Create logger for debug information."""
        logger = logging.getLogger('vaitp.debug')
        logger.setLevel(logging.DEBUG)
        
        # File handler for debug data
        handler = RotatingFileHandler(
            os.path.join(self.log_dir, 'debug.jsonl'),
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        handler.setFormatter(StructuredFormatter(include_context=True))
        logger.addHandler(handler)
        
        return logger
    
    def get_contextual_logger(self, name: str, context: Optional[LogContext] = None) -> ContextualLogger:
        """Get or create a contextual logger."""
        if name not in self._contextual_loggers:
            self._contextual_loggers[name] = ContextualLogger(name, context)
        return self._contextual_loggers[name]
    
    def log_execution_start(self, config: Dict[str, Any]) -> None:
        """Log execution start with configuration."""
        self.execution_logger.info(
            "Execution started",
            extra={
                'event': 'execution_start',
                'config': config,
                'timestamp': time.time()
            }
        )
    
    def log_execution_end(self, duration: float, results_summary: Dict[str, Any]) -> None:
        """Log execution completion with summary."""
        self.execution_logger.info(
            f"Execution completed in {duration:.2f}s",
            extra={
                'event': 'execution_end',
                'duration': duration,
                'results_summary': results_summary,
                'timestamp': time.time()
            }
        )
    
    def log_performance_metrics(self, metrics: Dict[str, Any]) -> None:
        """Log performance metrics."""
        self.performance_logger.info(
            "Performance metrics",
            extra={
                'event': 'performance_metrics',
                'metrics': metrics,
                'timestamp': time.time()
            }
        )
    
    def log_debug_info(self, component: str, debug_data: Dict[str, Any]) -> None:
        """Log debug information."""
        self.debug_logger.debug(
            f"Debug info for {component}",
            extra={
                'event': 'debug_info',
                'component': component,
                'debug_data': debug_data,
                'timestamp': time.time()
            }
        )
    
    def create_execution_context(self, model_name: str, process_id: int, gpu_id: int) -> LogContext:
        """Create execution context for a model process."""
        return LogContext(
            model_name=model_name,
            process_id=process_id,
            gpu_id=gpu_id,
            execution_phase='model_execution',
            timestamp=time.time()
        )
    
    def set_log_level(self, level: str) -> None:
        """Set logging level for all loggers."""
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        
        logging.getLogger().setLevel(numeric_level)
        self.execution_logger.setLevel(numeric_level)
        self.performance_logger.setLevel(numeric_level)
        self.debug_logger.setLevel(numeric_level)
    
    def get_log_files(self) -> List[str]:
        """Get list of current log files."""
        log_files = []
        for filename in os.listdir(self.log_dir):
            if filename.endswith(('.log', '.jsonl')):
                log_files.append(os.path.join(self.log_dir, filename))
        return sorted(log_files)
    
    def analyze_logs(self, log_type: str = 'execution', hours: int = 24) -> Dict[str, Any]:
        """Analyze recent logs for patterns and issues."""
        log_file = os.path.join(self.log_dir, f'{log_type}.jsonl')
        
        if not os.path.exists(log_file):
            return {'error': f'Log file not found: {log_file}'}
        
        cutoff_time = time.time() - (hours * 3600)
        events = []
        errors = []
        warnings = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # Parse timestamp
                        timestamp = log_entry.get('timestamp')
                        if isinstance(timestamp, str):
                            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                        
                        if timestamp and timestamp >= cutoff_time:
                            events.append(log_entry)
                            
                            if log_entry.get('level') == 'ERROR':
                                errors.append(log_entry)
                            elif log_entry.get('level') == 'WARNING':
                                warnings.append(log_entry)
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            return {'error': f'Failed to analyze logs: {e}'}
        
        # Analyze patterns
        analysis = {
            'time_range_hours': hours,
            'total_events': len(events),
            'error_count': len(errors),
            'warning_count': len(warnings),
            'event_types': {},
            'common_errors': {},
            'gpu_assignments': {},
            'process_events': {}
        }
        
        # Count event types
        for event in events:
            event_type = event.get('extra', {}).get('event', 'unknown')
            analysis['event_types'][event_type] = analysis['event_types'].get(event_type, 0) + 1
        
        # Analyze errors
        for error in errors:
            error_msg = error.get('message', 'Unknown error')
            analysis['common_errors'][error_msg] = analysis['common_errors'].get(error_msg, 0) + 1
        
        # Analyze GPU assignments
        for event in events:
            if event.get('extra', {}).get('gpu_assignment'):
                gpu_id = event.get('extra', {}).get('gpu_id')
                model_name = event.get('extra', {}).get('model_name')
                if gpu_id is not None and model_name:
                    analysis['gpu_assignments'][f'GPU_{gpu_id}'] = analysis['gpu_assignments'].get(f'GPU_{gpu_id}', [])
                    analysis['gpu_assignments'][f'GPU_{gpu_id}'].append(model_name)
        
        # Analyze process events
        for event in events:
            process_event = event.get('extra', {}).get('process_event')
            if process_event:
                analysis['process_events'][process_event] = analysis['process_events'].get(process_event, 0) + 1
        
        return analysis

# Global logging manager instance
_logging_manager: Optional[LoggingManager] = None

def get_logging_manager() -> LoggingManager:
    """Get global logging manager instance."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager

def setup_logging(log_dir: str = "logs", level: str = "INFO") -> LoggingManager:
    """Setup logging system for VAITP platform."""
    global _logging_manager
    _logging_manager = LoggingManager(log_dir)
    _logging_manager.set_log_level(level)
    return _logging_manager

def get_contextual_logger(name: str, **context_kwargs) -> ContextualLogger:
    """Get contextual logger with specified context."""
    context = LogContext(**context_kwargs)
    return get_logging_manager().get_contextual_logger(name, context)