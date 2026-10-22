"""
Real-time Monitoring Dashboard for VAITP Platform

This module provides real-time monitoring capabilities for parallel execution,
GPU usage, system resources, and process status with debugging utilities.

Requirements implemented:
- 3.4, 3.5: Real-time progress monitoring and system resource monitoring
- 4.5: Detailed logging and debugging capabilities
"""

import time
import json
import threading
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import os
import psutil
from collections import defaultdict, deque

from performance_optimizer import PerformanceOptimizer, GPUProfiler, SystemMonitor

logger = logging.getLogger(__name__)

@dataclass
class ProcessStatus:
    """Status information for a running process."""
    model_name: str
    process_id: int
    gpu_id: int
    status: str  # 'running', 'completed', 'failed', 'timeout'
    start_time: float
    current_task: str
    completed_tasks: int
    total_tasks: int
    error_message: Optional[str] = None
    
    @property
    def duration(self) -> float:
        """Calculate process duration."""
        return time.time() - self.start_time
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage."""
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class ExecutionMetrics:
    """Overall execution metrics."""
    total_processes: int
    running_processes: int
    completed_processes: int
    failed_processes: int
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    start_time: float
    estimated_completion_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        """Calculate total execution duration."""
        return time.time() - self.start_time
    
    @property
    def overall_progress_percent(self) -> float:
        """Calculate overall progress percentage."""
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        total_completed = self.completed_processes + self.failed_processes
        if total_completed == 0:
            return 0.0
        return (self.completed_processes / total_completed) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

class RealTimeMonitor:
    """Real-time monitoring system for parallel execution."""
    
    def __init__(self, update_interval: float = 1.0):
        """
        Initialize real-time monitor.
        
        Args:
            update_interval: Seconds between monitoring updates
        """
        self.update_interval = update_interval
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Process tracking
        self.process_status: Dict[str, ProcessStatus] = {}
        self.execution_metrics = ExecutionMetrics(
            total_processes=0,
            running_processes=0,
            completed_processes=0,
            failed_processes=0,
            total_tasks=0,
            completed_tasks=0,
            failed_tasks=0,
            start_time=time.time()
        )
        
        # Performance monitoring
        self.gpu_profiler = GPUProfiler(update_interval)
        self.system_monitor = SystemMonitor(update_interval)
        
        # Event callbacks
        self.status_callbacks: List[Callable] = []
        self.alert_callbacks: List[Callable] = []
        
        # Alert thresholds
        self.alert_thresholds = {
            'gpu_memory_percent': 90.0,
            'system_memory_percent': 85.0,
            'cpu_percent': 80.0,
            'process_timeout_minutes': 60.0,
            'error_rate_percent': 20.0
        }
        
        # Monitoring history
        self.status_history: deque = deque(maxlen=1000)
        self.alert_history: deque = deque(maxlen=100)
        
        logger.info("RealTimeMonitor initialized")
    
    def start_monitoring(self, gpu_ids: List[int]) -> None:
        """Start real-time monitoring."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.execution_metrics.start_time = time.time()
        
        # Start component monitoring
        self.gpu_profiler.start_monitoring(gpu_ids)
        self.system_monitor.start_monitoring()
        
        # Start main monitoring loop
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info(f"Started real-time monitoring for GPUs: {gpu_ids}")
    
    def stop_monitoring(self) -> None:
        """Stop real-time monitoring."""
        self.is_monitoring = False
        
        # Stop component monitoring
        self.gpu_profiler.stop_monitoring()
        self.system_monitor.stop_monitoring()
        
        # Stop main monitoring thread
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        
        logger.info("Stopped real-time monitoring")
    
    def register_process(self, model_name: str, process_id: int, gpu_id: int, total_tasks: int) -> None:
        """Register a new process for monitoring."""
        status = ProcessStatus(
            model_name=model_name,
            process_id=process_id,
            gpu_id=gpu_id,
            status='running',
            start_time=time.time(),
            current_task='initializing',
            completed_tasks=0,
            total_tasks=total_tasks
        )
        
        self.process_status[model_name] = status
        self.execution_metrics.total_processes += 1
        self.execution_metrics.running_processes += 1
        self.execution_metrics.total_tasks += total_tasks
        
        logger.info(f"Registered process: {model_name} (PID: {process_id}, GPU: {gpu_id})")
        self._notify_status_update()
    
    def update_process_progress(self, model_name: str, current_task: str, completed_tasks: int) -> None:
        """Update process progress."""
        if model_name not in self.process_status:
            logger.warning(f"Unknown process: {model_name}")
            return
        
        status = self.process_status[model_name]
        old_completed = status.completed_tasks
        
        status.current_task = current_task
        status.completed_tasks = completed_tasks
        
        # Update global metrics
        self.execution_metrics.completed_tasks += (completed_tasks - old_completed)
        
        logger.debug(f"Updated progress: {model_name} - {completed_tasks}/{status.total_tasks} tasks")
        self._notify_status_update()
    
    def complete_process(self, model_name: str, success: bool, error_message: Optional[str] = None) -> None:
        """Mark process as completed."""
        if model_name not in self.process_status:
            logger.warning(f"Unknown process: {model_name}")
            return
        
        status = self.process_status[model_name]
        status.status = 'completed' if success else 'failed'
        status.error_message = error_message
        
        # Update global metrics
        self.execution_metrics.running_processes -= 1
        if success:
            self.execution_metrics.completed_processes += 1
        else:
            self.execution_metrics.failed_processes += 1
            self.execution_metrics.failed_tasks += (status.total_tasks - status.completed_tasks)
        
        logger.info(f"Process {'completed' if success else 'failed'}: {model_name}")
        self._notify_status_update()
    
    def add_status_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback for status updates."""
        self.status_callbacks.append(callback)
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        # Get resource information
        gpu_info = self.gpu_profiler.get_all_gpu_info()
        system_info = self.system_monitor.get_system_info()
        
        # Calculate estimated completion time
        if self.execution_metrics.completed_tasks > 0 and self.execution_metrics.running_processes > 0:
            avg_task_time = self.execution_metrics.duration / self.execution_metrics.completed_tasks
            remaining_tasks = self.execution_metrics.total_tasks - self.execution_metrics.completed_tasks
            estimated_remaining_time = remaining_tasks * avg_task_time
            self.execution_metrics.estimated_completion_time = time.time() + estimated_remaining_time
        
        return {
            'timestamp': time.time(),
            'execution_metrics': self.execution_metrics.to_dict(),
            'process_status': {name: status.to_dict() for name, status in self.process_status.items()},
            'gpu_info': [info.to_dict() for info in gpu_info],
            'system_info': system_info.to_dict() if system_info else None,
            'alerts': list(self.alert_history)[-10:]  # Last 10 alerts
        }
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.is_monitoring:
            try:
                # Check for alerts
                self._check_alerts()
                
                # Update status history
                current_status = self.get_current_status()
                self.status_history.append(current_status)
                
                # Notify callbacks
                self._notify_status_update()
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.update_interval)
    
    def _check_alerts(self) -> None:
        """Check for alert conditions."""
        current_time = time.time()
        alerts = []
        
        # Check GPU memory usage
        gpu_info = self.gpu_profiler.get_all_gpu_info()
        for info in gpu_info:
            if info.usage_percent > self.alert_thresholds['gpu_memory_percent']:
                alerts.append({
                    'type': 'gpu_memory_high',
                    'severity': 'warning',
                    'message': f'GPU {info.gpu_id} memory usage is {info.usage_percent:.1f}%',
                    'gpu_id': info.gpu_id,
                    'value': info.usage_percent,
                    'threshold': self.alert_thresholds['gpu_memory_percent'],
                    'timestamp': current_time
                })
        
        # Check system memory usage
        system_info = self.system_monitor.get_system_info()
        if system_info and system_info.memory_percent > self.alert_thresholds['system_memory_percent']:
            alerts.append({
                'type': 'system_memory_high',
                'severity': 'warning',
                'message': f'System memory usage is {system_info.memory_percent:.1f}%',
                'value': system_info.memory_percent,
                'threshold': self.alert_thresholds['system_memory_percent'],
                'timestamp': current_time
            })
        
        # Check CPU usage
        if system_info and system_info.cpu_percent > self.alert_thresholds['cpu_percent']:
            alerts.append({
                'type': 'cpu_usage_high',
                'severity': 'info',
                'message': f'CPU usage is {system_info.cpu_percent:.1f}%',
                'value': system_info.cpu_percent,
                'threshold': self.alert_thresholds['cpu_percent'],
                'timestamp': current_time
            })
        
        # Check for long-running processes
        timeout_threshold = self.alert_thresholds['process_timeout_minutes'] * 60
        for model_name, status in self.process_status.items():
            if status.status == 'running' and status.duration > timeout_threshold:
                alerts.append({
                    'type': 'process_timeout',
                    'severity': 'error',
                    'message': f'Process {model_name} has been running for {status.duration/60:.1f} minutes',
                    'model_name': model_name,
                    'duration_minutes': status.duration / 60,
                    'threshold_minutes': self.alert_thresholds['process_timeout_minutes'],
                    'timestamp': current_time
                })
        
        # Check error rate
        if self.execution_metrics.total_processes > 0:
            error_rate = (self.execution_metrics.failed_processes / self.execution_metrics.total_processes) * 100
            if error_rate > self.alert_thresholds['error_rate_percent']:
                alerts.append({
                    'type': 'high_error_rate',
                    'severity': 'error',
                    'message': f'Error rate is {error_rate:.1f}%',
                    'value': error_rate,
                    'threshold': self.alert_thresholds['error_rate_percent'],
                    'failed_processes': self.execution_metrics.failed_processes,
                    'total_processes': self.execution_metrics.total_processes,
                    'timestamp': current_time
                })
        
        # Store and notify alerts
        for alert in alerts:
            self.alert_history.append(alert)
            logger.warning(f"Alert: {alert['message']}")
            self._notify_alert(alert)
    
    def _notify_status_update(self) -> None:
        """Notify status update callbacks."""
        if not self.status_callbacks:
            return
        
        try:
            current_status = self.get_current_status()
            for callback in self.status_callbacks:
                callback(current_status)
        except Exception as e:
            logger.error(f"Error in status callback: {e}")
    
    def _notify_alert(self, alert: Dict[str, Any]) -> None:
        """Notify alert callbacks."""
        if not self.alert_callbacks:
            return
        
        try:
            for callback in self.alert_callbacks:
                callback(alert)
        except Exception as e:
            logger.error(f"Error in alert callback: {e}")
    
    def save_monitoring_report(self, output_path: str) -> None:
        """Save comprehensive monitoring report."""
        report = {
            'monitoring_summary': {
                'start_time': self.execution_metrics.start_time,
                'end_time': time.time(),
                'duration': self.execution_metrics.duration,
                'update_interval': self.update_interval
            },
            'execution_metrics': self.execution_metrics.to_dict(),
            'process_status': {name: status.to_dict() for name, status in self.process_status.items()},
            'alert_summary': {
                'total_alerts': len(self.alert_history),
                'alert_types': list(set(alert['type'] for alert in self.alert_history)),
                'recent_alerts': list(self.alert_history)[-20:]  # Last 20 alerts
            },
            'performance_history': list(self.status_history)[-100:]  # Last 100 status updates
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Monitoring report saved to: {output_path}")

class DebugUtilities:
    """Debugging utilities for failed parallel executions."""
    
    def __init__(self, monitor: RealTimeMonitor):
        """
        Initialize debug utilities.
        
        Args:
            monitor: RealTimeMonitor instance for accessing execution data
        """
        self.monitor = monitor
        self.logger = logging.getLogger(__name__)
    
    def analyze_failed_processes(self) -> Dict[str, Any]:
        """Analyze failed processes and provide diagnostic information."""
        failed_processes = {
            name: status for name, status in self.monitor.process_status.items()
            if status.status == 'failed'
        }
        
        if not failed_processes:
            return {'message': 'No failed processes found'}
        
        analysis = {
            'failed_count': len(failed_processes),
            'failure_patterns': self._identify_failure_patterns(failed_processes),
            'resource_analysis': self._analyze_resource_usage_at_failures(failed_processes),
            'recommendations': self._generate_failure_recommendations(failed_processes)
        }
        
        return analysis
    
    def _identify_failure_patterns(self, failed_processes: Dict[str, ProcessStatus]) -> Dict[str, Any]:
        """Identify common patterns in process failures."""
        patterns = {
            'timeout_failures': [],
            'memory_failures': [],
            'gpu_failures': [],
            'unknown_failures': []
        }
        
        for name, status in failed_processes.items():
            error_msg = status.error_message or ''
            
            if 'timeout' in error_msg.lower():
                patterns['timeout_failures'].append(name)
            elif 'memory' in error_msg.lower() or 'oom' in error_msg.lower():
                patterns['memory_failures'].append(name)
            elif 'cuda' in error_msg.lower() or 'gpu' in error_msg.lower():
                patterns['gpu_failures'].append(name)
            else:
                patterns['unknown_failures'].append(name)
        
        return patterns
    
    def _analyze_resource_usage_at_failures(self, failed_processes: Dict[str, ProcessStatus]) -> Dict[str, Any]:
        """Analyze resource usage patterns when failures occurred."""
        # This would analyze historical resource data at failure times
        # For now, provide current resource analysis
        gpu_info = self.monitor.gpu_profiler.get_all_gpu_info()
        system_info = self.monitor.system_monitor.get_system_info()
        
        return {
            'current_gpu_usage': [
                {
                    'gpu_id': info.gpu_id,
                    'memory_percent': info.usage_percent,
                    'utilization_percent': info.utilization_percent
                }
                for info in gpu_info
            ],
            'current_system_usage': {
                'memory_percent': system_info.memory_percent if system_info else 0,
                'cpu_percent': system_info.cpu_percent if system_info else 0
            } if system_info else {}
        }
    
    def _generate_failure_recommendations(self, failed_processes: Dict[str, ProcessStatus]) -> List[str]:
        """Generate recommendations based on failure analysis."""
        recommendations = []
        
        # Analyze failure patterns
        timeout_count = len([p for p in failed_processes.values() if 'timeout' in (p.error_message or '').lower()])
        memory_count = len([p for p in failed_processes.values() if 'memory' in (p.error_message or '').lower()])
        
        if timeout_count > 0:
            recommendations.append(f"Consider increasing timeout_per_model (current failures: {timeout_count})")
        
        if memory_count > 0:
            recommendations.append(f"Consider reducing num_gpus or using smaller models (memory failures: {memory_count})")
        
        # Check resource usage
        gpu_info = self.monitor.gpu_profiler.get_all_gpu_info()
        high_memory_gpus = [info for info in gpu_info if info.usage_percent > 90]
        
        if high_memory_gpus:
            recommendations.append(f"GPU memory usage is high on {len(high_memory_gpus)} GPUs. Consider reducing parallel workers.")
        
        system_info = self.monitor.system_monitor.get_system_info()
        if system_info and system_info.memory_percent > 85:
            recommendations.append("System memory usage is high. Consider reducing parallel processes or increasing RAM.")
        
        if not recommendations:
            recommendations.append("No specific recommendations. Check individual error messages for details.")
        
        return recommendations
    
    def generate_debug_report(self, output_path: str) -> None:
        """Generate comprehensive debug report."""
        report = {
            'debug_timestamp': time.time(),
            'execution_summary': self.monitor.execution_metrics.to_dict(),
            'process_analysis': {
                'total_processes': len(self.monitor.process_status),
                'running_processes': len([p for p in self.monitor.process_status.values() if p.status == 'running']),
                'completed_processes': len([p for p in self.monitor.process_status.values() if p.status == 'completed']),
                'failed_processes': len([p for p in self.monitor.process_status.values() if p.status == 'failed'])
            },
            'failure_analysis': self.analyze_failed_processes(),
            'resource_status': {
                'gpu_info': [info.to_dict() for info in self.monitor.gpu_profiler.get_all_gpu_info()],
                'system_info': self.monitor.system_monitor.get_system_info().to_dict() if self.monitor.system_monitor.get_system_info() else None
            },
            'recent_alerts': list(self.monitor.alert_history)[-20:],
            'process_details': {name: status.to_dict() for name, status in self.monitor.process_status.items()}
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Debug report saved to: {output_path}")
    
    def print_status_summary(self) -> None:
        """Print a formatted status summary to console."""
        metrics = self.monitor.execution_metrics
        
        print("\n" + "="*60)
        print("VAITP PLATFORM EXECUTION STATUS")
        print("="*60)
        
        print(f"Duration: {metrics.duration:.1f}s")
        print(f"Overall Progress: {metrics.overall_progress_percent:.1f}%")
        print(f"Success Rate: {metrics.success_rate:.1f}%")
        
        print(f"\nProcesses: {metrics.completed_processes}/{metrics.total_processes} completed")
        print(f"Tasks: {metrics.completed_tasks}/{metrics.total_tasks} completed")
        
        if metrics.failed_processes > 0:
            print(f"⚠️  Failed Processes: {metrics.failed_processes}")
        
        # Show running processes
        running_processes = [p for p in self.monitor.process_status.values() if p.status == 'running']
        if running_processes:
            print(f"\n🔄 Running Processes ({len(running_processes)}):")
            for process in running_processes:
                print(f"  • {process.model_name}: {process.progress_percent:.1f}% ({process.current_task})")
        
        # Show recent alerts
        recent_alerts = list(self.monitor.alert_history)[-5:]
        if recent_alerts:
            print(f"\n⚠️  Recent Alerts ({len(recent_alerts)}):")
            for alert in recent_alerts:
                print(f"  • {alert['type']}: {alert['message']}")
        
        print("="*60)

def create_monitoring_dashboard(update_interval: float = 1.0) -> RealTimeMonitor:
    """
    Factory function to create a RealTimeMonitor instance.
    
    Args:
        update_interval: Seconds between monitoring updates
        
    Returns:
        Configured RealTimeMonitor instance
    """
    return RealTimeMonitor(update_interval)