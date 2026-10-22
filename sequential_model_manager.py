#!/usr/bin/env python3
"""
Sequential Model Manager for VAITP Framework

This module implements proper sequential model management:
1. Load one model at a time
2. Use the model for all required tasks
3. Completely unload and cleanup before loading next model
4. Aggressive memory management between models
"""

import gc
import os
import logging
import psutil
from typing import Optional, Dict, Any, List, Callable
from contextlib import contextmanager
from llama_cpp import Llama
from adaptive_resource_manager import get_resource_manager

logger = logging.getLogger(__name__)

class SequentialModelManager:
    """Manages models sequentially with proper cleanup."""
    
    def __init__(self):
        self.current_model: Optional[Llama] = None
        self.current_model_name: Optional[str] = None
        self.resource_manager = get_resource_manager()
        
    def _aggressive_cleanup(self):
        """Perform aggressive memory cleanup."""
        logger.info("🧹 Performing aggressive memory cleanup...")
        
        # Clear current model
        if self.current_model is not None:
            try:
                del self.current_model
                self.current_model = None
                self.current_model_name = None
                logger.info("   ✅ Model instance deleted")
            except Exception as e:
                logger.warning(f"   ⚠️  Error deleting model: {e}")
        
        # Python garbage collection (multiple passes)
        for i in range(3):
            collected = gc.collect()
            if collected > 0:
                logger.info(f"   🗑️  GC pass {i+1}: collected {collected} objects")
        
        # Clear GPU caches
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                torch.cuda.synchronize()
                logger.info("   🎮 CUDA cache cleared")
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                torch.mps.empty_cache()
                logger.info("   🍎 MPS cache cleared")
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"   ⚠️  GPU cache cleanup error: {e}")
        
        # Force memory trim (Linux/macOS)
        try:
            if hasattr(os, 'sync'):
                os.sync()
            
            # Try to trim malloc heap
            import ctypes
            try:
                if os.name == 'posix':
                    libc = ctypes.CDLL("libc.so.6")
                    libc.malloc_trim(0)
                    logger.info("   🔧 Malloc heap trimmed")
            except:
                pass  # Not available on all systems
        except Exception as e:
            logger.debug(f"   Memory trim error: {e}")
        
        # Log memory state after cleanup
        memory = psutil.virtual_memory()
        logger.info(f"   📊 Memory after cleanup: {memory.used/(1024**3):.1f}GB used, "
                   f"{memory.available/(1024**3):.1f}GB available ({memory.percent:.1f}%)")
    
    def _load_model_with_fallback(self, model_path: str, model_name: str) -> Optional[Llama]:
        """Load a model with multiple fallback configurations."""
        from main_orchestrator import initialize_llm
        
        logger.info(f"🚀 Loading {model_name}...")
        
        # Cleanup before loading
        self._aggressive_cleanup()
        
        # Get memory state before loading
        memory_before = psutil.virtual_memory()
        logger.info(f"   📊 Memory before loading: {memory_before.available/(1024**3):.1f}GB available")
        
        try:
            # Use the existing initialize_llm function which has fallback logic
            llm = initialize_llm(model_path)
            
            if llm is not None:
                self.current_model = llm
                self.current_model_name = model_name
                
                # Log memory state after loading
                memory_after = psutil.virtual_memory()
                memory_used = (memory_before.available - memory_after.available) / (1024**3)
                logger.info(f"   ✅ {model_name} loaded successfully!")
                logger.info(f"   📊 Memory used by model: ~{memory_used:.1f}GB")
                logger.info(f"   📊 Memory after loading: {memory_after.available/(1024**3):.1f}GB available")
                
                return llm
            else:
                logger.error(f"   ❌ Failed to load {model_name}")
                return None
                
        except Exception as e:
            logger.error(f"   ❌ Error loading {model_name}: {e}")
            return None
    
    def unload_current_model(self):
        """Unload the current model and cleanup memory."""
        if self.current_model is not None:
            logger.info(f"🔄 Unloading {self.current_model_name}...")
            self._aggressive_cleanup()
            logger.info(f"   ✅ {self.current_model_name} unloaded")
        else:
            logger.debug("   ℹ️  No model currently loaded")
    
    @contextmanager
    def load_model_context(self, model_path: str, model_name: str):
        """Context manager for loading a model temporarily."""
        model = None
        try:
            # Unload any existing model first
            self.unload_current_model()
            
            # Load the new model
            model = self._load_model_with_fallback(model_path, model_name)
            
            if model is None:
                raise RuntimeError(f"Failed to load model {model_name}")
            
            yield model
            
        finally:
            # Always cleanup, even if an exception occurred
            self.unload_current_model()
    
    def process_model_sequentially(self, model_name: str, model_path: str, 
                                 task_function: Callable[[Llama, str], Any]) -> Any:
        """
        Process a single model with proper lifecycle management.
        
        Args:
            model_name: Name of the model
            model_path: Path to the model file
            task_function: Function to execute with the loaded model
                          Should accept (llm_instance, model_name) and return results
        
        Returns:
            Results from task_function or None if model loading failed
        """
        logger.info(f"🎯 Processing {model_name} sequentially...")
        
        try:
            with self.load_model_context(model_path, model_name) as llm:
                logger.info(f"   🔄 Executing tasks for {model_name}...")
                
                # Execute the task function
                results = task_function(llm, model_name)
                
                logger.info(f"   ✅ Tasks completed for {model_name}")
                return results
                
        except Exception as e:
            logger.error(f"   ❌ Error processing {model_name}: {e}")
            return None
        finally:
            # Ensure cleanup happens
            logger.info(f"   🧹 Final cleanup for {model_name}")
            self._aggressive_cleanup()
    
    def process_models_batch(self, models_info: List[Dict[str, str]], 
                           task_function: Callable[[Llama, str], Any]) -> List[Any]:
        """
        Process multiple models sequentially.
        
        Args:
            models_info: List of dicts with 'name' and 'path' keys
            task_function: Function to execute for each model
        
        Returns:
            List of results from each model
        """
        logger.info(f"🚀 Processing {len(models_info)} models sequentially...")
        
        results = []
        
        for i, model_info in enumerate(models_info, 1):
            model_name = model_info['name']
            model_path = model_info['path']
            
            logger.info(f"📋 Model {i}/{len(models_info)}: {model_name}")
            
            # Check if model file exists
            if not os.path.exists(model_path):
                logger.error(f"   ❌ Model file not found: {model_path}")
                results.append(None)
                continue
            
            # Process the model
            result = self.process_model_sequentially(model_name, model_path, task_function)
            results.append(result)
            
            # Log progress
            if result is not None:
                logger.info(f"   ✅ {model_name} completed successfully")
            else:
                logger.error(f"   ❌ {model_name} failed")
            
            # Memory status between models
            memory = psutil.virtual_memory()
            logger.info(f"   📊 Memory between models: {memory.available/(1024**3):.1f}GB available")
        
        logger.info(f"🎉 Sequential processing complete! {sum(1 for r in results if r is not None)}/{len(results)} models succeeded")
        
        return results
    
    def get_memory_status(self) -> Dict[str, float]:
        """Get current memory status."""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total_gb': memory.total / (1024**3),
            'available_gb': memory.available / (1024**3),
            'used_gb': memory.used / (1024**3),
            'percent': memory.percent,
            'swap_total_gb': swap.total / (1024**3),
            'swap_used_gb': swap.used / (1024**3),
            'swap_percent': swap.percent
        }
    
    def log_memory_status(self, context: str = ""):
        """Log current memory status."""
        status = self.get_memory_status()
        context_str = f" ({context})" if context else ""
        
        logger.info(f"📊 Memory Status{context_str}:")
        logger.info(f"   RAM: {status['used_gb']:.1f}/{status['total_gb']:.1f}GB "
                   f"({status['percent']:.1f}%), {status['available_gb']:.1f}GB available")
        
        if status['swap_total_gb'] > 0:
            logger.info(f"   Swap: {status['swap_used_gb']:.1f}/{status['swap_total_gb']:.1f}GB "
                       f"({status['swap_percent']:.1f}%)")

# Global instance
_sequential_manager = None

def get_sequential_manager() -> SequentialModelManager:
    """Get the global sequential model manager."""
    global _sequential_manager
    if _sequential_manager is None:
        _sequential_manager = SequentialModelManager()
    return _sequential_manager

def process_models_sequentially(models_info: List[Dict[str, str]], 
                              task_function: Callable[[Llama, str], Any]) -> List[Any]:
    """
    Convenience function to process models sequentially.
    
    Args:
        models_info: List of dicts with 'name' and 'path' keys
        task_function: Function to execute for each model
    
    Returns:
        List of results from each model
    """
    manager = get_sequential_manager()
    return manager.process_models_batch(models_info, task_function)