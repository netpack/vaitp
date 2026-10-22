#!/usr/bin/env python3
"""
Memory management utilities to prevent system crashes.
"""

import os
import psutil
import logging
from typing import List, Dict, Tuple
from config import CODER_MODELS
from adaptive_resource_manager import get_resource_manager

logger = logging.getLogger(__name__)

class MemoryManager:
    """Manages memory usage and prevents system crashes."""
    
    def __init__(self, max_memory_percent: float = 85.0):
        """
        Initialize memory manager.
        
        Args:
            max_memory_percent: Maximum system memory usage before taking action
        """
        self.max_memory_percent = max_memory_percent
        self.total_memory_gb = psutil.virtual_memory().total / (1024**3)
        
    def get_system_memory_info(self) -> Dict[str, float]:
        """Get current system memory information."""
        memory = psutil.virtual_memory()
        return {
            'total_gb': memory.total / (1024**3),
            'available_gb': memory.available / (1024**3),
            'used_gb': memory.used / (1024**3),
            'percent': memory.percent,
            'free_gb': memory.free / (1024**3)
        }
    
    def get_model_size_gb(self, model_name: str) -> float:
        """Get the size of a model file in GB."""
        if model_name not in CODER_MODELS:
            return 0.0
            
        model_path = CODER_MODELS[model_name]['path']
        if not os.path.exists(model_path):
            return 0.0
            
        size_bytes = os.path.getsize(model_path)
        return size_bytes / (1024**3)
    
    def estimate_model_memory_usage(self, model_name: str) -> float:
        """
        Estimate memory usage for a model in GB.
        
        This is a rough estimate based on model file size.
        Actual usage can be 2-4x the file size depending on quantization and context.
        """
        file_size_gb = self.get_model_size_gb(model_name)
        
        # Rough estimates based on model size and quantization
        if file_size_gb < 1:  # 1B models
            return file_size_gb * 2.5  # ~2-3GB RAM usage
        elif file_size_gb < 2:  # 1.7B models  
            return file_size_gb * 3.0  # ~3-4GB RAM usage
        elif file_size_gb < 3:  # 3B models
            return file_size_gb * 3.5  # ~4-6GB RAM usage
        elif file_size_gb < 5:  # 7B models
            return file_size_gb * 4.0  # ~8-12GB RAM usage
        else:  # 8B+ models
            return file_size_gb * 4.5  # ~12-16GB RAM usage
    
    def can_load_model(self, model_name: str, safety_margin_gb: float = 2.0) -> bool:
        """
        Check if a model can be safely loaded without causing memory issues.
        
        Args:
            model_name: Name of the model to check
            safety_margin_gb: Safety margin in GB to keep free
            
        Returns:
            True if model can be safely loaded
        """
        memory_info = self.get_system_memory_info()
        estimated_usage = self.estimate_model_memory_usage(model_name)
        
        # Check if we have enough available memory
        available_memory = memory_info['available_gb']
        required_memory = estimated_usage + safety_margin_gb
        
        can_load = available_memory >= required_memory
        
        if not can_load:
            logger.warning(
                f"Model {model_name} requires ~{estimated_usage:.1f}GB but only "
                f"{available_memory:.1f}GB available (need {required_memory:.1f}GB with safety margin)"
            )
        
        return can_load
    
    def filter_models_by_memory(self, model_names: List[str]) -> Tuple[List[str], List[str]]:
        """
        Filter models based on available memory.
        
        Args:
            model_names: List of model names to filter
            
        Returns:
            Tuple of (safe_models, skipped_models)
        """
        memory_info = self.get_system_memory_info()
        logger.info(f"System memory: {memory_info['used_gb']:.1f}GB used, "
                   f"{memory_info['available_gb']:.1f}GB available "
                   f"({memory_info['percent']:.1f}%)")
        
        safe_models = []
        skipped_models = []
        
        # Sort models by estimated memory usage (smallest first)
        model_sizes = [(name, self.estimate_model_memory_usage(name)) for name in model_names]
        model_sizes.sort(key=lambda x: x[1])
        
        for model_name, estimated_usage in model_sizes:
            if self.can_load_model(model_name):
                safe_models.append(model_name)
                logger.info(f"✅ {model_name}: ~{estimated_usage:.1f}GB estimated usage - SAFE")
            else:
                skipped_models.append(model_name)
                logger.warning(f"⚠️  {model_name}: ~{estimated_usage:.1f}GB estimated usage - SKIPPED (insufficient memory)")
        
        return safe_models, skipped_models
    
    def should_force_cpu_mode(self) -> bool:
        """Check if we should force CPU-only mode due to memory pressure."""
        memory_info = self.get_system_memory_info()
        return memory_info['percent'] > self.max_memory_percent
    
    def cleanup_memory(self):
        """Force garbage collection and memory cleanup."""
        import gc
        gc.collect()
        
        # Try to clear any cached data
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                torch.mps.empty_cache()
        except Exception as e:
            logger.debug(f"Error during GPU cache cleanup: {e}")
    
    def get_memory_recommendations(self, model_names: List[str]) -> Dict[str, str]:
        """Get recommendations for memory optimization."""
        memory_info = self.get_system_memory_info()
        recommendations = {}
        
        if memory_info['percent'] > 80:
            recommendations['memory_pressure'] = (
                f"High memory usage ({memory_info['percent']:.1f}%). "
                "Consider running fewer models or using smaller models."
            )
        
        large_models = [name for name in model_names 
                       if self.estimate_model_memory_usage(name) > 8.0]
        
        if large_models and memory_info['total_gb'] < 32:
            recommendations['large_models'] = (
                f"Large models detected ({len(large_models)} models >8GB). "
                "Consider running them separately or using CPU-only mode."
            )
        
        return recommendations

def create_memory_safe_config(original_models: List[str], max_memory_percent: float = 80.0) -> List[str]:
    """
    Create a memory-safe model list based on available system memory using adaptive resource manager.
    
    Args:
        original_models: Original list of models to run
        max_memory_percent: Maximum memory usage threshold
        
    Returns:
        Filtered list of models that can be safely run
    """
    # Use the new adaptive resource manager
    resource_manager = get_resource_manager()
    
    # Get optimized model order
    optimized_models = resource_manager.optimize_model_order(original_models)
    
    safe_models = []
    skipped_models = []
    
    for model_name in optimized_models:
        can_run, reason = resource_manager.can_run_model(model_name)
        if can_run:
            safe_models.append(model_name)
            logger.info(f"✅ {model_name}: {reason}")
        else:
            skipped_models.append(model_name)
            logger.warning(f"⚠️  {model_name}: {reason}")
    
    if skipped_models:
        logger.warning(f"Skipped {len(skipped_models)} models due to resource constraints: {skipped_models}")
        logger.info(f"Running {len(safe_models)} resource-safe models: {safe_models}")
    
    # Print resource report
    resource_manager.print_resource_report()
    
    return safe_models