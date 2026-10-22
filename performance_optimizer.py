"""
Performance Optimization Module for VAITP Platform

This module provides GPU memory profiling, dynamic load balancing, and performance
monitoring capabilities for parallel execution optimization.

Requirements implemented:
- 1.6: Performance optimization and resource usage monitoring
- 3.4, 3.5: Resource monitoring and reporting capabilities
"""

import os
import time
import json
import psutil
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ProcessPoolExecutor
import subprocess
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

@dataclass
class GPUMemoryInfo:
    """GPU memory usage information."""
    gpu_id: int
    total_mb: int
    used_mb: int
    free_mb: int
    utilization_percent: float
    temperature: Optional[int] = None
    power_usage: Optional[int] = None
    
    @property
    def usage_percent(self) -> float:
        """Calculate memory usage percentage."""
        return (self.used_mb / self.total_mb * 100) if self.total_mb > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class SystemResourceInfo:
    """System resource usage information."""
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_usage_percent: float
    load_average: Tuple[float, float, float]
    timestamp: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class ProcessPerformanceMetrics:
    """Performance metrics for a single process/model."""
    model_name: str
    process_id: int
    gpu_id: int
    start_time: float
    end_time: Optional[float] = None
    peak_gpu_memory_mb: int = 0
    peak_cpu_percent: float = 0.0
    peak_system_memory_mb: float = 0.0
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    average_task_time: float = 0.0
    
    @property
    def duration(self) -> float:
        """Calculate process duration."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def throughput_tasks_per_second(self) -> float:
        """Calculate task throughput."""
        duration = self.duration
        return self.completed_tasks / duration if duration > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

class GPUProfiler:
    """GPU memory and utilization profiler."""
    
    def __init__(self, monitoring_interval: float = 1.0):
        """
        Initialize GPU profiler.
        
        Args:
            monitoring_interval: Seconds between monitoring samples
        """
        self.monitoring_interval = monitoring_interval
        self.gpu_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
    
    def get_gpu_info(self, gpu_id: int) -> Optional[GPUMemoryInfo]:
        """Get current GPU information (supports NVIDIA CUDA and Apple MPS)."""
        import platform
        import torch
        
        # Handle Apple MPS
        if platform.system() == "Darwin" and torch.backends.mps.is_available():
            try:
                import psutil
                # MPS doesn't provide detailed GPU metrics like CUDA
                # Return estimated values based on system resources
                total_memory = psutil.virtual_memory().total // (1024 * 1024)  # MB
                estimated_gpu_memory = min(total_memory // 4, 16384)  # Estimate max 16GB
                
                return GPUMemoryInfo(
                    gpu_id=gpu_id,
                    total_mb=estimated_gpu_memory,
                    used_mb=0,  # MPS doesn't provide used memory info
                    free_mb=estimated_gpu_memory,
                    utilization_percent=0.0,  # MPS doesn't provide utilization info
                    temperature=None,  # MPS doesn't provide temperature info
                    power_usage=None   # MPS doesn't provide power info
                )
            except Exception as e:
                logger.warning(f"Failed to get MPS info for GPU {gpu_id}: {e}")
                return None
        
        # Handle NVIDIA CUDA
        try:
            # Get memory info
            result = subprocess.run([
                'nvidia-smi', '--query-gpu=memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu,power.draw',
                '--format=csv,noheader,nounits', f'--id={gpu_id}'
            ], capture_output=True, text=True, check=True)
            
            values = result.stdout.strip().split(', ')
            
            return GPUMemoryInfo(
                gpu_id=gpu_id,
                total_mb=int(values[0]),
                used_mb=int(values[1]),
                free_mb=int(values[2]),
                utilization_percent=float(values[3]),
                temperature=int(values[4]) if values[4] != '[Not Supported]' else None,
                power_usage=int(float(values[5])) if values[5] != '[Not Supported]' else None
            )
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError, IndexError) as e:
            # Silently return None for MPS systems where nvidia-smi is expected to fail
            if platform.system() != "Darwin":
                logger.warning(f"Failed to get GPU {gpu_id} info: {e}")
            return None
    
    def get_all_gpu_info(self) -> List[GPUMemoryInfo]:
        """Get information for all available GPUs (supports NVIDIA CUDA and Apple MPS)."""
        import platform
        import torch
        
        gpu_info = []
        
        # Handle Apple MPS
        if platform.system() == "Darwin" and torch.backends.mps.is_available():
            info = self.get_gpu_info(0)  # MPS uses device 0
            if info:
                gpu_info.append(info)
            return gpu_info
        
        # Handle NVIDIA CUDA
        try:
            result = subprocess.run([
                'nvidia-smi', '--query-gpu=index',
                '--format=csv,noheader,nounits'
            ], capture_output=True, text=True, check=True)
            
            gpu_ids = [int(line.strip()) for line in result.stdout.strip().split('\n') if line.strip()]
            
            for gpu_id in gpu_ids:
                info = self.get_gpu_info(gpu_id)
                if info:
                    gpu_info.append(info)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # Silently handle for MPS systems where nvidia-smi is expected to fail
            if platform.system() != "Darwin":
                logger.warning(f"Failed to enumerate GPUs: {e}")
        
        return gpu_info
    
    def start_monitoring(self, gpu_ids: List[int]) -> None:
        """Start continuous GPU monitoring."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(gpu_ids,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started GPU monitoring for GPUs: {gpu_ids}")
    
    def stop_monitoring(self) -> None:
        """Stop GPU monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        logger.info("Stopped GPU monitoring")
    
    def _monitor_loop(self, gpu_ids: List[int]) -> None:
        """Continuous monitoring loop."""
        while self.is_monitoring:
            timestamp = time.time()
            for gpu_id in gpu_ids:
                info = self.get_gpu_info(gpu_id)
                if info:
                    self.gpu_history[gpu_id].append((timestamp, info))
            time.sleep(self.monitoring_interval)
    
    def get_gpu_history(self, gpu_id: int, duration_seconds: float = 300) -> List[Tuple[float, GPUMemoryInfo]]:
        """Get GPU history for the specified duration."""
        cutoff_time = time.time() - duration_seconds
        return [(ts, info) for ts, info in self.gpu_history[gpu_id] if ts >= cutoff_time]
    
    def get_peak_memory_usage(self, gpu_id: int, duration_seconds: float = 300) -> int:
        """Get peak memory usage for a GPU in the specified duration."""
        history = self.get_gpu_history(gpu_id, duration_seconds)
        if not history:
            return 0
        return max(info.used_mb for _, info in history)
    
    def get_average_utilization(self, gpu_id: int, duration_seconds: float = 300) -> float:
        """Get average GPU utilization for the specified duration."""
        history = self.get_gpu_history(gpu_id, duration_seconds)
        if not history:
            return 0.0
        return sum(info.utilization_percent for _, info in history) / len(history)

class SystemMonitor:
    """System resource monitor."""
    
    def __init__(self, monitoring_interval: float = 1.0):
        """
        Initialize system monitor.
        
        Args:
            monitoring_interval: Seconds between monitoring samples
        """
        self.monitoring_interval = monitoring_interval
        self.resource_history: deque = deque(maxlen=1000)
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
    
    def get_system_info(self) -> SystemResourceInfo:
        """Get current system resource information."""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return SystemResourceInfo(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=memory.percent,
            memory_used_gb=memory.used / (1024**3),
            memory_total_gb=memory.total / (1024**3),
            disk_usage_percent=disk.percent,
            load_average=os.getloadavg() if hasattr(os, 'getloadavg') else (0.0, 0.0, 0.0),
            timestamp=time.time()
        )
    
    def start_monitoring(self) -> None:
        """Start continuous system monitoring."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Started system resource monitoring")
    
    def stop_monitoring(self) -> None:
        """Stop system monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        logger.info("Stopped system resource monitoring")
    
    def _monitor_loop(self) -> None:
        """Continuous monitoring loop."""
        while self.is_monitoring:
            info = self.get_system_info()
            self.resource_history.append(info)
            time.sleep(self.monitoring_interval)
    
    def get_resource_history(self, duration_seconds: float = 300) -> List[SystemResourceInfo]:
        """Get system resource history for the specified duration."""
        cutoff_time = time.time() - duration_seconds
        return [info for info in self.resource_history if info.timestamp >= cutoff_time]
    
    def get_peak_memory_usage(self, duration_seconds: float = 300) -> float:
        """Get peak memory usage percentage in the specified duration."""
        history = self.get_resource_history(duration_seconds)
        if not history:
            return 0.0
        return max(info.memory_percent for info in history)
    
    def get_average_cpu_usage(self, duration_seconds: float = 300) -> float:
        """Get average CPU usage in the specified duration."""
        history = self.get_resource_history(duration_seconds)
        if not history:
            return 0.0
        return sum(info.cpu_percent for info in history) / len(history)

class DynamicLoadBalancer:
    """Dynamic load balancer for GPU assignment."""
    
    def __init__(self, gpu_profiler: GPUProfiler):
        """
        Initialize load balancer.
        
        Args:
            gpu_profiler: GPU profiler instance for monitoring
        """
        self.gpu_profiler = gpu_profiler
        self.gpu_assignments: Dict[int, List[str]] = defaultdict(list)  # gpu_id -> [model_names]
        self.model_metrics: Dict[str, ProcessPerformanceMetrics] = {}
    
    def get_optimal_gpu_assignment(self, available_gpus: List[int], model_name: str) -> int:
        """
        Get optimal GPU assignment based on current load and memory usage.
        
        Args:
            available_gpus: List of available GPU IDs
            model_name: Name of the model to assign
            
        Returns:
            Optimal GPU ID for assignment
        """
        if not available_gpus:
            return 0  # Fallback to CPU
        
        gpu_scores = {}
        
        for gpu_id in available_gpus:
            score = self._calculate_gpu_score(gpu_id)
            gpu_scores[gpu_id] = score
        
        # Select GPU with the best (lowest) score
        optimal_gpu = min(gpu_scores.keys(), key=lambda x: gpu_scores[x])
        
        # Update assignments
        self.gpu_assignments[optimal_gpu].append(model_name)
        
        logger.info(f"Assigned {model_name} to GPU {optimal_gpu} (score: {gpu_scores[optimal_gpu]:.2f})")
        return optimal_gpu
    
    def _calculate_gpu_score(self, gpu_id: int) -> float:
        """
        Calculate a score for GPU assignment (lower is better).
        
        Factors considered:
        - Current memory usage
        - Current utilization
        - Number of assigned models
        - Historical performance
        """
        gpu_info = self.gpu_profiler.get_gpu_info(gpu_id)
        if not gpu_info:
            return float('inf')  # Avoid unavailable GPUs
        
        # Base score from current usage
        memory_score = gpu_info.usage_percent / 100.0  # 0-1
        utilization_score = gpu_info.utilization_percent / 100.0  # 0-1
        
        # Penalty for number of assigned models
        assignment_penalty = len(self.gpu_assignments[gpu_id]) * 0.2
        
        # Historical performance factor
        avg_utilization = self.gpu_profiler.get_average_utilization(gpu_id, 60)  # Last minute
        historical_score = avg_utilization / 100.0
        
        # Combine scores (weighted)
        total_score = (
            memory_score * 0.4 +
            utilization_score * 0.3 +
            assignment_penalty * 0.2 +
            historical_score * 0.1
        )
        
        return total_score
    
    def release_gpu_assignment(self, gpu_id: int, model_name: str) -> None:
        """Release GPU assignment when model completes."""
        if model_name in self.gpu_assignments[gpu_id]:
            self.gpu_assignments[gpu_id].remove(model_name)
            logger.info(f"Released {model_name} from GPU {gpu_id}")
    
    def get_load_balance_report(self) -> Dict[str, Any]:
        """Get current load balancing status."""
        gpu_loads = {}
        for gpu_id, models in self.gpu_assignments.items():
            gpu_info = self.gpu_profiler.get_gpu_info(gpu_id)
            gpu_loads[gpu_id] = {
                'assigned_models': models,
                'model_count': len(models),
                'memory_usage_percent': gpu_info.usage_percent if gpu_info else 0,
                'utilization_percent': gpu_info.utilization_percent if gpu_info else 0
            }
        
        return {
            'gpu_loads': gpu_loads,
            'total_assigned_models': sum(len(models) for models in self.gpu_assignments.values()),
            'load_balance_score': self._calculate_load_balance_score()
        }
    
    def _calculate_load_balance_score(self) -> float:
        """Calculate load balance score (0-1, where 1 is perfectly balanced)."""
        if not self.gpu_assignments:
            return 1.0
        
        model_counts = [len(models) for models in self.gpu_assignments.values()]
        if not model_counts:
            return 1.0
        
        # Calculate coefficient of variation (lower is more balanced)
        mean_count = sum(model_counts) / len(model_counts)
        if mean_count == 0:
            return 1.0
        
        variance = sum((count - mean_count) ** 2 for count in model_counts) / len(model_counts)
        std_dev = variance ** 0.5
        cv = std_dev / mean_count
        
        # Convert to balance score (1 - normalized CV)
        return max(0.0, 1.0 - min(cv, 1.0))

class PerformanceOptimizer:
    """Main performance optimization coordinator."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize performance optimizer.
        
        Args:
            config: Configuration dictionary with optimization settings
        """
        self.config = config or {}
        self.monitoring_interval = self.config.get('monitoring_interval', 1.0)
        self.optimization_enabled = self.config.get('enable_optimization', True)
        
        # Initialize components
        self.gpu_profiler = GPUProfiler(self.monitoring_interval)
        self.system_monitor = SystemMonitor(self.monitoring_interval)
        self.load_balancer = DynamicLoadBalancer(self.gpu_profiler)
        
        # Performance tracking
        self.process_metrics: Dict[str, ProcessPerformanceMetrics] = {}
        self.optimization_history: List[Dict[str, Any]] = []
        
        logger.info("PerformanceOptimizer initialized")
    
    def start_monitoring(self, gpu_ids: List[int]) -> None:
        """Start all monitoring components."""
        self.gpu_profiler.start_monitoring(gpu_ids)
        self.system_monitor.start_monitoring()
        logger.info(f"Started performance monitoring for GPUs: {gpu_ids}")
    
    def stop_monitoring(self) -> None:
        """Stop all monitoring components."""
        self.gpu_profiler.stop_monitoring()
        self.system_monitor.stop_monitoring()
        logger.info("Stopped performance monitoring")
    
    def get_optimal_worker_count(self, available_gpus: List[int], model_count: int) -> int:
        """
        Calculate optimal number of worker processes based on system resources.
        
        Args:
            available_gpus: List of available GPU IDs
            model_count: Number of models to process
            
        Returns:
            Optimal number of worker processes
        """
        if not available_gpus:
            # CPU-only mode
            cpu_count = psutil.cpu_count(logical=False)  # Physical cores
            return min(model_count, max(1, cpu_count // 2))
        
        # GPU mode - consider GPU memory and model requirements
        gpu_info = self.gpu_profiler.get_all_gpu_info()
        if not gpu_info:
            return len(available_gpus)
        
        # Estimate memory per model (this could be made configurable)
        estimated_memory_per_model_mb = self.config.get('estimated_memory_per_model_mb', 4000)
        
        suitable_gpus = 0
        for info in gpu_info:
            if info.gpu_id in available_gpus and info.free_mb >= estimated_memory_per_model_mb:
                suitable_gpus += 1
        
        optimal_workers = min(model_count, max(1, suitable_gpus))
        
        logger.info(f"Calculated optimal worker count: {optimal_workers} "
                   f"(GPUs: {len(available_gpus)}, Models: {model_count}, "
                   f"Suitable GPUs: {suitable_gpus})")
        
        return optimal_workers
    
    def get_optimal_gpu_assignment(self, available_gpus: List[int], model_name: str) -> int:
        """Get optimal GPU assignment using load balancer."""
        return self.load_balancer.get_optimal_gpu_assignment(available_gpus, model_name)
    
    def register_process_start(self, model_name: str, process_id: int, gpu_id: int) -> None:
        """Register the start of a model process."""
        metrics = ProcessPerformanceMetrics(
            model_name=model_name,
            process_id=process_id,
            gpu_id=gpu_id,
            start_time=time.time()
        )
        self.process_metrics[model_name] = metrics
        logger.info(f"Registered process start: {model_name} (PID: {process_id}, GPU: {gpu_id})")
    
    def register_process_end(self, model_name: str, task_results: Dict[str, Any]) -> None:
        """Register the end of a model process with results."""
        if model_name not in self.process_metrics:
            logger.warning(f"Process end registered for unknown model: {model_name}")
            return
        
        metrics = self.process_metrics[model_name]
        metrics.end_time = time.time()
        metrics.completed_tasks = task_results.get('completed_tasks', 0)
        metrics.failed_tasks = task_results.get('failed_tasks', 0)
        metrics.total_tasks = metrics.completed_tasks + metrics.failed_tasks
        
        if metrics.completed_tasks > 0:
            metrics.average_task_time = metrics.duration / metrics.completed_tasks
        
        # Get peak resource usage
        metrics.peak_gpu_memory_mb = self.gpu_profiler.get_peak_memory_usage(
            metrics.gpu_id, metrics.duration
        )
        
        # Release GPU assignment
        self.load_balancer.release_gpu_assignment(metrics.gpu_id, model_name)
        
        logger.info(f"Registered process end: {model_name} "
                   f"(Duration: {metrics.duration:.2f}s, "
                   f"Tasks: {metrics.completed_tasks}/{metrics.total_tasks}, "
                   f"Peak GPU Memory: {metrics.peak_gpu_memory_mb}MB)")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        current_time = time.time()
        
        # System overview
        system_info = self.system_monitor.get_system_info()
        gpu_info = self.gpu_profiler.get_all_gpu_info()
        
        # Process metrics summary
        process_summary = {}
        for model_name, metrics in self.process_metrics.items():
            process_summary[model_name] = metrics.to_dict()
        
        # Load balancing status
        load_balance_report = self.load_balancer.get_load_balance_report()
        
        # Performance statistics
        completed_processes = [m for m in self.process_metrics.values() if m.end_time is not None]
        
        performance_stats = {
            'total_processes': len(self.process_metrics),
            'completed_processes': len(completed_processes),
            'running_processes': len(self.process_metrics) - len(completed_processes),
            'average_duration': sum(m.duration for m in completed_processes) / len(completed_processes) if completed_processes else 0,
            'total_tasks_completed': sum(m.completed_tasks for m in completed_processes),
            'total_tasks_failed': sum(m.failed_tasks for m in completed_processes),
            'average_throughput': sum(m.throughput_tasks_per_second for m in completed_processes) / len(completed_processes) if completed_processes else 0
        }
        
        return {
            'timestamp': current_time,
            'system_info': system_info.to_dict(),
            'gpu_info': [info.to_dict() for info in gpu_info],
            'process_metrics': process_summary,
            'load_balance_report': load_balance_report,
            'performance_stats': performance_stats,
            'optimization_enabled': self.optimization_enabled,
            'monitoring_interval': self.monitoring_interval
        }
    
    def save_performance_report(self, output_path: str) -> None:
        """Save performance report to file."""
        report = self.get_performance_report()
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Performance report saved to: {output_path}")
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on performance data."""
        recommendations = []
        
        # Analyze GPU utilization
        gpu_info = self.gpu_profiler.get_all_gpu_info()
        for info in gpu_info:
            if info.usage_percent > 90:
                recommendations.append({
                    'type': 'gpu_memory',
                    'severity': 'high',
                    'gpu_id': info.gpu_id,
                    'message': f'GPU {info.gpu_id} memory usage is {info.usage_percent:.1f}%. Consider reducing batch size or model count.',
                    'suggestion': 'Reduce models per GPU or increase GPU memory'
                })
            elif info.utilization_percent < 30:
                recommendations.append({
                    'type': 'gpu_utilization',
                    'severity': 'medium',
                    'gpu_id': info.gpu_id,
                    'message': f'GPU {info.gpu_id} utilization is low ({info.utilization_percent:.1f}%). Consider increasing workload.',
                    'suggestion': 'Assign more models to this GPU or increase batch size'
                })
        
        # Analyze load balancing
        load_balance_score = self.load_balancer._calculate_load_balance_score()
        if load_balance_score < 0.7:
            recommendations.append({
                'type': 'load_balance',
                'severity': 'medium',
                'message': f'Load balancing score is {load_balance_score:.2f}. Workload distribution could be improved.',
                'suggestion': 'Enable dynamic load balancing or manually redistribute models'
            })
        
        # Analyze system resources
        system_info = self.system_monitor.get_system_info()
        if system_info.memory_percent > 85:
            recommendations.append({
                'type': 'system_memory',
                'severity': 'high',
                'message': f'System memory usage is {system_info.memory_percent:.1f}%. Risk of swapping.',
                'suggestion': 'Reduce number of parallel processes or increase system RAM'
            })
        
        if system_info.cpu_percent > 80:
            recommendations.append({
                'type': 'cpu_usage',
                'severity': 'medium',
                'message': f'CPU usage is {system_info.cpu_percent:.1f}%. May impact performance.',
                'suggestion': 'Reduce CPU-intensive operations or increase CPU resources'
            })
        
        return recommendations
    
    def cleanup(self) -> None:
        """Cleanup resources and stop monitoring."""
        self.stop_monitoring()
        self.process_metrics.clear()
        self.optimization_history.clear()
        logger.info("PerformanceOptimizer cleaned up")

def create_performance_optimizer(config: Optional[Dict[str, Any]] = None) -> PerformanceOptimizer:
    """
    Factory function to create a PerformanceOptimizer instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured PerformanceOptimizer instance
    """
    return PerformanceOptimizer(config)