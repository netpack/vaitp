#!/usr/bin/env python3
"""
Adaptive Resource Manager for VAITP Framework

This module provides intelligent resource management that:
1. Dynamically checks available memory, GPU, and CPU resources
2. Prioritizes GPU/MPS usage but falls back to CPU when needed
3. Adjusts model configurations based on available resources
4. Ensures the framework does everything possible to complete tasks
"""

import os
import gc
import psutil
import logging
import platform
import shutil
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from config import CODER_MODELS, REASONING_MODELS, LLM_N_CTX, LLM_N_THREADS, LLM_N_GPU_LAYERS

logger = logging.getLogger(__name__)

@dataclass
class ResourceProfile:
    """System resource profile."""
    total_memory_gb: float
    available_memory_gb: float
    memory_percent: float
    cpu_count: int
    cpu_percent: float
    has_mps: bool
    has_cuda: bool
    gpu_memory_gb: Optional[float] = None
    swap_total_gb: float = 0.0
    swap_available_gb: float = 0.0
    ssd_total_gb: float = 0.0
    ssd_available_gb: float = 0.0
    ollm_available: bool = False
    ollm_version: Optional[str] = None

@dataclass
class ModelResourceRequirement:
    """Resource requirements for a model."""
    model_name: str
    file_size_gb: float
    estimated_memory_gb: float
    min_memory_gb: float
    optimal_memory_gb: float
    can_use_gpu: bool
    can_use_cpu: bool
    priority: int  # Lower number = higher priority

@dataclass
class AdaptiveConfig:
    """Adaptive configuration for model loading."""
    n_ctx: int
    n_threads: int
    n_gpu_layers: int
    use_mmap: bool
    use_mlock: bool
    batch_size: int
    use_swap: bool
    config_name: str
    estimated_memory_gb: float

class AdaptiveResourceManager:
    """Manages system resources adaptively for optimal performance."""
    
    def __init__(self, safety_margin_gb: float = 0.5, enable_swap: bool = True):
        """
        Initialize the adaptive resource manager.
        
        Args:
            safety_margin_gb: Memory safety margin to maintain
            enable_swap: Whether to use swap/pagefile when needed
        """
        self.safety_margin_gb = safety_margin_gb
        self.enable_swap = enable_swap
        self.resource_profile = self._get_resource_profile()
        self.model_requirements = self._analyze_model_requirements()
        
        logger.info(f"🧠 Adaptive Resource Manager initialized")
        logger.info(f"   System: {self.resource_profile.total_memory_gb:.1f}GB RAM, "
                   f"{self.resource_profile.cpu_count} CPUs")
        logger.info(f"   GPU: MPS={self.resource_profile.has_mps}, "
                   f"CUDA={self.resource_profile.has_cuda}")
        if self.resource_profile.swap_total_gb > 0:
            logger.info(f"   Swap: {self.resource_profile.swap_total_gb:.1f}GB total, "
                       f"{self.resource_profile.swap_available_gb:.1f}GB available")
    
    def _get_resource_profile(self) -> ResourceProfile:
        """Get current system resource profile."""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Check GPU availability
        has_mps = False
        has_cuda = False
        gpu_memory_gb = None
        
        try:
            import torch
            has_mps = platform.system() == "Darwin" and torch.backends.mps.is_available()
            has_cuda = torch.cuda.is_available()
            
            if has_cuda:
                gpu_memory_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            elif has_mps:
                # MPS doesn't have a direct way to get memory, estimate based on system
                gpu_memory_gb = min(memory.total / (1024**3) * 0.7, 16.0)  # Estimate
        except ImportError:
            logger.warning("PyTorch not available, GPU detection disabled")
        
        # Get SSD information
        ssd_total_gb, ssd_available_gb = self._get_ssd_info()
        
        # Get oLLM availability and version
        ollm_available, ollm_version = self._get_ollm_info()
        
        return ResourceProfile(
            total_memory_gb=memory.total / (1024**3),
            available_memory_gb=memory.available / (1024**3),
            memory_percent=memory.percent,
            cpu_count=psutil.cpu_count(),
            cpu_percent=psutil.cpu_percent(interval=1),
            has_mps=has_mps,
            has_cuda=has_cuda,
            gpu_memory_gb=gpu_memory_gb,
            swap_total_gb=swap.total / (1024**3),
            swap_available_gb=(swap.total - swap.used) / (1024**3),
            ssd_total_gb=ssd_total_gb,
            ssd_available_gb=ssd_available_gb,
            ollm_available=ollm_available,
            ollm_version=ollm_version
        )
    
    def _get_ssd_info(self) -> Tuple[float, float]:
        """
        Get SSD space information across different operating systems.
        
        Returns:
            Tuple[float, float]: (total_gb, available_gb)
        """
        try:
            # Get disk usage for the current working directory
            # This should represent the main storage device
            disk_usage = shutil.disk_usage(os.getcwd())
            total_gb = disk_usage.total / (1024**3)
            available_gb = disk_usage.free / (1024**3)
            
            return total_gb, available_gb
        except Exception as e:
            logger.warning(f"Failed to get SSD information: {e}")
            return 0.0, 0.0
    
    def _get_ollm_info(self) -> Tuple[bool, Optional[str]]:
        """
        Get oLLM availability and version information.
        
        Returns:
            Tuple[bool, Optional[str]]: (is_available, version)
        """
        try:
            from ollm_manager import OLLMManager
            available = OLLMManager.is_ollm_available()
            version = OLLMManager.get_ollm_version() if available else None
            return available, version
        except ImportError:
            logger.warning("OLLMManager not available")
            return False, None
        except Exception as e:
            logger.warning(f"Failed to get oLLM information: {e}")
            return False, None
    
    def _analyze_model_requirements(self) -> Dict[str, ModelResourceRequirement]:
        """Analyze resource requirements for all models."""
        requirements = {}
        
        # Analyze both CODER_MODELS and REASONING_MODELS
        all_models = {**CODER_MODELS, **REASONING_MODELS}
        
        for model_name, model_info in all_models.items():
            model_path = model_info['path']
            
            if not os.path.exists(model_path):
                logger.warning(f"Model file not found: {model_path}")
                continue
            
            file_size_gb = os.path.getsize(model_path) / (1024**3)
            
            # More realistic memory requirements based on actual hardware performance
            # These estimates are more aggressive since the user confirmed all models work
            if file_size_gb < 1:  # 1B models
                estimated_memory = file_size_gb * 1.8  # More realistic
                min_memory = file_size_gb * 1.2
                optimal_memory = file_size_gb * 2.5
                priority = 1
            elif file_size_gb < 2:  # 1.7B models
                estimated_memory = file_size_gb * 2.2  # More realistic
                min_memory = file_size_gb * 1.5
                optimal_memory = file_size_gb * 3.0
                priority = 2
            elif file_size_gb < 3:  # 3B models
                estimated_memory = file_size_gb * 2.5  # More realistic
                min_memory = file_size_gb * 1.8
                optimal_memory = file_size_gb * 3.5
                priority = 3
            elif file_size_gb < 5:  # 7B models - MUCH more realistic
                estimated_memory = file_size_gb * 1.8  # Much more aggressive
                min_memory = file_size_gb * 1.3
                optimal_memory = file_size_gb * 2.5
                priority = 4
            else:  # 8B+ models - MUCH more realistic
                estimated_memory = file_size_gb * 1.9  # Much more aggressive
                min_memory = file_size_gb * 1.4
                optimal_memory = file_size_gb * 2.8
                priority = 5
            
            requirements[model_name] = ModelResourceRequirement(
                model_name=model_name,
                file_size_gb=file_size_gb,
                estimated_memory_gb=estimated_memory,
                min_memory_gb=min_memory,
                optimal_memory_gb=optimal_memory,
                can_use_gpu=True,  # Most models can use GPU
                can_use_cpu=True,  # All models can use CPU
                priority=priority
            )
        
        return requirements
    
    def refresh_resources(self) -> ResourceProfile:
        """Refresh current resource profile."""
        self.resource_profile = self._get_resource_profile()
        return self.resource_profile
    
    def get_adaptive_config(self, model_name: str, force_cpu: bool = False) -> List[AdaptiveConfig]:
        """
        Get adaptive configurations for a model, ordered by preference.
        
        Args:
            model_name: Name of the model
            force_cpu: Force CPU-only mode
            
        Returns:
            List of configurations to try, ordered by preference
        """
        if model_name not in self.model_requirements:
            logger.error(f"Model {model_name} not found in requirements")
            return []
        
        req = self.model_requirements[model_name]
        profile = self.refresh_resources()
        
        configs = []
        
        # Calculate available memory including swap if enabled
        total_available = profile.available_memory_gb
        if self.enable_swap and profile.swap_available_gb > 0:
            total_available += profile.swap_available_gb * 0.5  # Conservative swap usage
        
        # GPU/MPS configurations (if not forced to CPU)
        if not force_cpu and (profile.has_mps or profile.has_cuda):
            gpu_type = "MPS" if profile.has_mps else "CUDA"
            
            # Special optimized configuration for deepthink-7b on MPS
            if model_name == "deepthink-7b" and profile.has_mps:
                configs.append(AdaptiveConfig(
                    n_ctx=8192,  # Use larger context for better performance
                    n_threads=4,  # Optimal for MPS
                    n_gpu_layers=35,  # High GPU layers for MPS acceleration
                    use_mmap=True,
                    use_mlock=False,
                    batch_size=1,
                    use_swap=False,  # Avoid swap for better performance
                    config_name="MPS Optimized DeepThink",
                    estimated_memory_gb=req.min_memory_gb * 0.9
                ))
            
            # Optimal GPU configuration - more aggressive
            if total_available >= req.optimal_memory_gb:  # No safety margin for optimal
                configs.append(AdaptiveConfig(
                    n_ctx=min(LLM_N_CTX, 16384),
                    n_threads=LLM_N_THREADS,
                    n_gpu_layers=LLM_N_GPU_LAYERS,
                    use_mmap=True,
                    use_mlock=False,  # Don't lock memory to allow flexibility
                    batch_size=1,
                    use_swap=self.enable_swap,
                    config_name=f"{gpu_type} Optimal",
                    estimated_memory_gb=req.optimal_memory_gb
                ))
            
            # Balanced GPU configuration - more aggressive
            if total_available >= req.estimated_memory_gb:  # No safety margin
                configs.append(AdaptiveConfig(
                    n_ctx=min(LLM_N_CTX, 8192),
                    n_threads=LLM_N_THREADS,
                    n_gpu_layers=max(30, LLM_N_GPU_LAYERS // 2),  # More GPU layers
                    use_mmap=True,
                    use_mlock=False,
                    batch_size=1,
                    use_swap=self.enable_swap,
                    config_name=f"{gpu_type} Balanced",
                    estimated_memory_gb=req.estimated_memory_gb
                ))
            
            # Minimal GPU configuration - much more aggressive
            if total_available >= req.min_memory_gb:  # No safety margin
                configs.append(AdaptiveConfig(
                    n_ctx=min(4096, LLM_N_CTX),
                    n_threads=LLM_N_THREADS,  # Keep full threads
                    n_gpu_layers=max(20, LLM_N_GPU_LAYERS // 3),  # More GPU layers
                    use_mmap=True,
                    use_mlock=False,
                    batch_size=1,
                    use_swap=self.enable_swap,
                    config_name=f"{gpu_type} Minimal",
                    estimated_memory_gb=req.min_memory_gb
                ))
            
            # Aggressive GPU configuration for large models
            if req.file_size_gb > 4:  # For 7B+ models, add an aggressive config
                # Use model's native context window for better performance
                model_context = req.context_window if hasattr(req, 'context_window') else 8192
                configs.append(AdaptiveConfig(
                    n_ctx=min(model_context, 8192),  # Use model's context but cap at 8K for memory
                    n_threads=LLM_N_THREADS,
                    n_gpu_layers=max(25, LLM_N_GPU_LAYERS // 2),  # More GPU layers for better performance
                    use_mmap=True,
                    use_mlock=False,
                    batch_size=1,
                    use_swap=True,  # Force swap usage
                    config_name=f"{gpu_type} Aggressive",
                    estimated_memory_gb=req.min_memory_gb * 0.8  # Even more aggressive
                ))
        
        # CPU configurations (always available as fallback)
        cpu_memory_req = req.estimated_memory_gb * 0.7  # CPU uses less memory
        
        # Optimal CPU configuration
        if total_available >= cpu_memory_req:  # No safety margin
            configs.append(AdaptiveConfig(
                n_ctx=min(LLM_N_CTX, 8192),
                n_threads=profile.cpu_count,
                n_gpu_layers=0,
                use_mmap=True,
                use_mlock=False,
                batch_size=1,
                use_swap=self.enable_swap,
                config_name="CPU Optimal",
                estimated_memory_gb=cpu_memory_req
            ))
        
        # Balanced CPU configuration
        balanced_cpu_req = req.min_memory_gb * 0.8
        if total_available >= balanced_cpu_req:
            configs.append(AdaptiveConfig(
                n_ctx=4096,
                n_threads=profile.cpu_count,
                n_gpu_layers=0,
                use_mmap=True,
                use_mlock=False,
                batch_size=1,
                use_swap=self.enable_swap,
                config_name="CPU Balanced",
                estimated_memory_gb=balanced_cpu_req
            ))
        
        # Minimal CPU configuration (last resort)
        minimal_cpu_req = req.min_memory_gb * 0.5  # Very aggressive
        if total_available >= minimal_cpu_req:
            configs.append(AdaptiveConfig(
                n_ctx=2048,
                n_threads=max(2, profile.cpu_count // 2),  # Keep more threads
                n_gpu_layers=0,
                use_mmap=True,
                use_mlock=False,
                batch_size=1,
                use_swap=True,  # Force swap
                config_name="CPU Minimal",
                estimated_memory_gb=minimal_cpu_req
            ))
        
        # Emergency configuration (uses swap aggressively) - always add this
        if self.enable_swap and profile.swap_total_gb > 0:
            configs.append(AdaptiveConfig(
                n_ctx=1024,
                n_threads=max(2, profile.cpu_count // 4),  # Keep some threads
                n_gpu_layers=0,
                use_mmap=True,
                use_mlock=False,
                batch_size=1,
                use_swap=True,
                config_name="Emergency Swap Mode",
                estimated_memory_gb=req.min_memory_gb * 0.3  # Very aggressive
            ))
        
        # Ultra-aggressive configuration (for models that should work)
        configs.append(AdaptiveConfig(
            n_ctx=1024,
            n_threads=max(1, profile.cpu_count // 4),
            n_gpu_layers=0,
            use_mmap=True,
            use_mlock=False,
            batch_size=1,
            use_swap=True,
            config_name="Ultra-Aggressive Mode",
            estimated_memory_gb=req.file_size_gb * 1.1  # Just slightly more than file size
        ))
        
        if not configs:
            logger.error(f"No viable configuration found for {model_name}")
            logger.error(f"Available: {total_available:.1f}GB, Required: {req.min_memory_gb:.1f}GB")
        
        return configs
    
    def optimize_model_order(self, model_names: List[str]) -> List[str]:
        """
        Optimize the order of model execution based on resource requirements.
        
        Args:
            model_names: List of model names to optimize
            
        Returns:
            Optimized order of model names
        """
        # Get requirements for requested models
        model_reqs = []
        for name in model_names:
            if name in self.model_requirements:
                model_reqs.append(self.model_requirements[name])
            else:
                logger.warning(f"Model {name} not found in requirements, skipping")
        
        # Sort by priority (smaller models first) and memory requirements
        model_reqs.sort(key=lambda x: (x.priority, x.estimated_memory_gb))
        
        return [req.model_name for req in model_reqs]
    
    def can_run_model(self, model_name: str) -> Tuple[bool, str]:
        """
        Check if a model can be run with current resources.
        More permissive since user confirmed all models work on this hardware.
        
        Args:
            model_name: Name of the model to check
            
        Returns:
            Tuple of (can_run, reason)
        """
        if model_name not in self.model_requirements:
            return False, f"Model {model_name} not found"
        
        req = self.model_requirements[model_name]
        profile = self.refresh_resources()
        
        total_available = profile.available_memory_gb
        if self.enable_swap and profile.swap_available_gb > 0:
            total_available += profile.swap_available_gb * 0.8  # More aggressive swap usage
        
        # Very aggressive check - if total system memory can theoretically fit the model, try it
        total_system_memory = profile.total_memory_gb
        
        # If the model file size is less than 60% of total system memory, attempt to run it
        if req.file_size_gb <= total_system_memory * 0.6:
            return True, f"Attempting with {total_available:.1f}GB available (model {req.file_size_gb:.1f}GB fits in {total_system_memory:.1f}GB system)"
        
        # Original logic as fallback
        min_required = req.file_size_gb + 1.0  # Just file size + 1GB buffer
        
        if total_available >= min_required:
            return True, f"Can run with {total_available:.1f}GB available (need ~{min_required:.1f}GB)"
        else:
            # Even if we don't have enough, still try if it's close
            if total_available >= req.file_size_gb * 0.8:  # If we have 80% of file size
                return True, f"Attempting with {total_available:.1f}GB (aggressive mode)"
            else:
                return False, f"Insufficient memory: need ~{min_required:.1f}GB, have {total_available:.1f}GB"
    
    def cleanup_memory(self):
        """Aggressive memory cleanup."""
        logger.info("🧹 Performing aggressive memory cleanup...")
        
        # Python garbage collection
        collected = gc.collect()
        logger.info(f"   Collected {collected} objects")
        
        # Clear GPU cache if available
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                logger.info("   Cleared CUDA cache")
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                torch.mps.empty_cache()
                logger.info("   Cleared MPS cache")
        except ImportError:
            pass
        
        # Force memory cleanup
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            libc.malloc_trim(0)
            logger.info("   Trimmed malloc heap")
        except:
            pass  # Not available on all systems
    
    def get_resource_summary(self) -> Dict[str, Any]:
        """Get a summary of current resource usage."""
        profile = self.refresh_resources()
        
        return {
            "memory": {
                "total_gb": profile.total_memory_gb,
                "available_gb": profile.available_memory_gb,
                "used_percent": profile.memory_percent,
                "swap_total_gb": profile.swap_total_gb,
                "swap_available_gb": profile.swap_available_gb
            },
            "cpu": {
                "count": profile.cpu_count,
                "usage_percent": profile.cpu_percent
            },
            "gpu": {
                "has_mps": profile.has_mps,
                "has_cuda": profile.has_cuda,
                "memory_gb": profile.gpu_memory_gb
            },
            "storage": {
                "ssd_total_gb": profile.ssd_total_gb,
                "ssd_available_gb": profile.ssd_available_gb
            },
            "ollm": {
                "available": profile.ollm_available,
                "version": profile.ollm_version
            },
            "models": {
                "total_models": len(self.model_requirements),
                "runnable_models": len([name for name in self.model_requirements.keys() 
                                      if self.can_run_model(name)[0]]),
                "ollm_recommended": len([name for name in self.model_requirements.keys() 
                                       if self.should_use_ollm(name)[0]])
            }
        }
    
    def print_resource_report(self):
        """Print a detailed resource report."""
        summary = self.get_resource_summary()
        
        print("\n" + "="*60)
        print("🧠 ADAPTIVE RESOURCE MANAGER REPORT")
        print("="*60)
        
        print(f"💾 Memory:")
        print(f"   Total: {summary['memory']['total_gb']:.1f} GB")
        print(f"   Available: {summary['memory']['available_gb']:.1f} GB")
        print(f"   Used: {summary['memory']['used_percent']:.1f}%")
        if summary['memory']['swap_total_gb'] > 0:
            print(f"   Swap: {summary['memory']['swap_available_gb']:.1f}/{summary['memory']['swap_total_gb']:.1f} GB available")
        
        print(f"\n🖥️  CPU:")
        print(f"   Cores: {summary['cpu']['count']}")
        print(f"   Usage: {summary['cpu']['usage_percent']:.1f}%")
        
        print(f"\n🎮 GPU:")
        print(f"   MPS: {'✅' if summary['gpu']['has_mps'] else '❌'}")
        print(f"   CUDA: {'✅' if summary['gpu']['has_cuda'] else '❌'}")
        if summary['gpu']['memory_gb']:
            print(f"   Memory: {summary['gpu']['memory_gb']:.1f} GB")
        
        print(f"\n💾 Storage:")
        print(f"   SSD Total: {summary['storage']['ssd_total_gb']:.1f} GB")
        print(f"   SSD Available: {summary['storage']['ssd_available_gb']:.1f} GB")
        
        print(f"\n🚀 oLLM:")
        print(f"   Available: {'✅' if summary['ollm']['available'] else '❌'}")
        if summary['ollm']['version']:
            print(f"   Version: {summary['ollm']['version']}")
        
        print(f"\n🤖 Models:")
        print(f"   Total: {summary['models']['total_models']}")
        print(f"   Runnable: {summary['models']['runnable_models']}")
        print(f"   oLLM Recommended: {summary['models']['ollm_recommended']}")
        
        print("\n📊 Model Analysis:")
        for name, req in sorted(self.model_requirements.items(), key=lambda x: x[1].priority):
            can_run, reason = self.can_run_model(name)
            status = "✅" if can_run else "❌"
            print(f"   {status} {name}: {req.file_size_gb:.1f}GB file, ~{req.estimated_memory_gb:.1f}GB RAM")
        
        print("="*60)
    
    def should_use_ollm(self, model_name: str) -> Tuple[bool, str]:
        """
        Determine if oLLM should be used for a model based on size vs VRAM comparison.
        
        Args:
            model_name: Name of the model to check
            
        Returns:
            Tuple[bool, str]: (should_use_ollm, reason)
        """
        import time
        from ollm_logging import get_ollm_logger
        
        start_time = time.time()
        ollm_logger = get_ollm_logger()
        
        # Check if oLLM is available
        profile = self.refresh_resources()
        if not profile.ollm_available:
            selection_time = (time.time() - start_time) * 1000
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=0.0,  # Unknown model size
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="llamacpp",
                selection_reason="oLLM not available",
                selection_time_ms=selection_time
            )
            
            return False, "oLLM not available"
        
        # Check if model exists in requirements
        if model_name not in self.model_requirements:
            selection_time = (time.time() - start_time) * 1000
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=0.0,  # Unknown model size
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="llamacpp",
                selection_reason=f"Model {model_name} not found in requirements",
                selection_time_ms=selection_time
            )
            
            return False, f"Model {model_name} not found in requirements"
        
        req = self.model_requirements[model_name]
        
        # Get oLLM configuration to check thresholds
        from config import get_ollm_config
        ollm_config = get_ollm_config(model_name)
        
        # Check for forced oLLM usage
        if ollm_config.get('force_ollm', False):
            selection_time = (time.time() - start_time) * 1000
            reason = "Forced oLLM usage via configuration"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="ollm",
                selection_reason=reason,
                forced_backend="ollm",
                selection_time_ms=selection_time
            )
            
            return True, reason
        
        # Check for oLLM preference
        if ollm_config.get('prefer_ollm', False):
            selection_time = (time.time() - start_time) * 1000
            reason = "oLLM preferred via configuration"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="ollm",
                selection_reason=reason,
                selection_time_ms=selection_time
            )
            
            return True, reason
        
        # Check if oLLM is globally disabled
        if not ollm_config.get('enable_ollm', True):
            selection_time = (time.time() - start_time) * 1000
            reason = "oLLM disabled in configuration"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="llamacpp",
                selection_reason=reason,
                selection_time_ms=selection_time
            )
            
            return False, reason
        
        # Auto-detection logic based on memory requirements
        if not ollm_config.get('ollm_auto_detect', True):
            selection_time = (time.time() - start_time) * 1000
            reason = "oLLM auto-detection disabled"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="llamacpp",
                selection_reason=reason,
                selection_time_ms=selection_time
            )
            
            return False, reason
        
        # Memory threshold check
        memory_threshold_gb = ollm_config.get('ollm_memory_threshold_gb', 2.0)
        
        # Check if model would exceed VRAM capacity
        if profile.gpu_memory_gb is not None:
            # If model requires more VRAM than available, use oLLM
            if req.estimated_memory_gb > profile.gpu_memory_gb - memory_threshold_gb:
                selection_time = (time.time() - start_time) * 1000
                reason = f"Model needs {req.estimated_memory_gb:.1f}GB, GPU has {profile.gpu_memory_gb:.1f}GB (threshold: {memory_threshold_gb}GB)"
                
                # Log the backend selection decision
                ollm_logger.log_backend_selection(
                    model_name=model_name,
                    model_size_gb=req.file_size_gb,
                    available_vram_gb=profile.gpu_memory_gb,
                    available_ssd_gb=profile.ssd_available_gb,
                    backend_selected="ollm",
                    selection_reason=reason,
                    selection_time_ms=selection_time
                )
                
                return True, reason
        
        # Check if model would exceed available system memory
        total_available = profile.available_memory_gb
        if self.enable_swap and profile.swap_available_gb > 0:
            total_available += profile.swap_available_gb * 0.5
        
        # If model would use most of available memory, consider oLLM
        if req.estimated_memory_gb > total_available * 0.8:
            selection_time = (time.time() - start_time) * 1000
            reason = f"Model needs {req.estimated_memory_gb:.1f}GB, only {total_available:.1f}GB available"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="ollm",
                selection_reason=reason,
                selection_time_ms=selection_time
            )
            
            return True, reason
        
        # For large models (>4GB), prefer oLLM if it's available
        if req.file_size_gb > 4.0:
            selection_time = (time.time() - start_time) * 1000
            reason = f"Large model ({req.file_size_gb:.1f}GB) - oLLM recommended for memory efficiency"
            
            # Log the backend selection decision
            ollm_logger.log_backend_selection(
                model_name=model_name,
                model_size_gb=req.file_size_gb,
                available_vram_gb=profile.gpu_memory_gb or 0.0,
                available_ssd_gb=profile.ssd_available_gb,
                backend_selected="ollm",
                selection_reason=reason,
                selection_time_ms=selection_time
            )
            
            return True, reason
        
        # Default to llamacpp
        selection_time = (time.time() - start_time) * 1000
        reason = "Standard llama-cpp-python sufficient for this model"
        
        # Log the backend selection decision
        ollm_logger.log_backend_selection(
            model_name=model_name,
            model_size_gb=req.file_size_gb,
            available_vram_gb=profile.gpu_memory_gb or 0.0,
            available_ssd_gb=profile.ssd_available_gb,
            backend_selected="llamacpp",
            selection_reason=reason,
            selection_time_ms=selection_time
        )
        
        return False, reason
    
    def get_ollm_config(self, model_name: str) -> Dict[str, Any]:
        """
        Generate optimal oLLM configuration for a model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Dict[str, Any]: oLLM configuration parameters
        """
        profile = self.refresh_resources()
        
        # Get base oLLM configuration
        from config import get_ollm_config
        base_config = get_ollm_config(model_name)
        
        # Start with base configuration
        config = {
            'device': base_config.get('ollm_device', 'auto'),
            'logging': base_config.get('ollm_logging', True),
            'memory_threshold_gb': base_config.get('ollm_memory_threshold_gb', 2.0),
            'ssd_min_space_gb': base_config.get('ollm_ssd_min_space_gb', 10.0),
            'fallback_enabled': base_config.get('ollm_fallback_enabled', True)
        }
        
        # Auto-detect optimal device if set to 'auto'
        if config['device'] == 'auto':
            if profile.has_cuda:
                config['device'] = 'cuda'
            elif profile.has_mps:
                config['device'] = 'mps'
            else:
                config['device'] = 'cpu'
        
        # Add model-specific optimizations
        if model_name in self.model_requirements:
            req = self.model_requirements[model_name]
            
            # Adjust configuration based on model size
            if req.file_size_gb > 7.0:  # Large models
                config['offload_layers'] = 'auto'  # Let oLLM decide
                config['cache_size'] = 'large'
            elif req.file_size_gb > 3.0:  # Medium models
                config['offload_layers'] = 'partial'
                config['cache_size'] = 'medium'
            else:  # Small models
                config['offload_layers'] = 'minimal'
                config['cache_size'] = 'small'
        
        # Add SSD-specific optimizations
        if profile.ssd_available_gb > config['ssd_min_space_gb']:
            config['use_ssd_offload'] = True
            config['ssd_cache_size'] = min(profile.ssd_available_gb * 0.1, 5.0)  # Use up to 10% of SSD or 5GB
        else:
            config['use_ssd_offload'] = False
            logger.warning(f"Insufficient SSD space for oLLM: {profile.ssd_available_gb:.1f}GB available, {config['ssd_min_space_gb']:.1f}GB required")
        
        return config
    
    def validate_ollm_compatibility(self, model_path: str) -> bool:
        """
        Check if a model is compatible with oLLM.
        
        Args:
            model_path: Path to the model file
            
        Returns:
            bool: True if model is compatible with oLLM
        """
        if not os.path.exists(model_path):
            logger.warning(f"Model file not found: {model_path}")
            return False
        
        # Check file extension - oLLM typically works with GGUF files
        if not model_path.lower().endswith('.gguf'):
            logger.warning(f"Model {model_path} is not a GGUF file - may not be compatible with oLLM")
            return False
        
        # Check file size - very small files might not be valid models
        try:
            file_size_gb = os.path.getsize(model_path) / (1024**3)
            if file_size_gb < 0.1:  # Less than 100MB
                logger.warning(f"Model file {model_path} is very small ({file_size_gb:.2f}GB) - may not be a valid model")
                return False
        except OSError as e:
            logger.error(f"Cannot access model file {model_path}: {e}")
            return False
        
        # Check if oLLM is available
        profile = self.refresh_resources()
        if not profile.ollm_available:
            logger.warning("oLLM is not available - cannot validate compatibility")
            return False
        
        # Additional validation could be added here, such as:
        # - Checking model metadata
        # - Verifying model format compatibility
        # - Testing model loading (expensive, so not done here)
        
        return True
    
    def calculate_optimal_ollm_settings(self, model_name: str) -> Dict[str, Any]:
        """
        Calculate optimal oLLM settings based on available SSD space and speed.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Dict[str, Any]: Optimal oLLM settings
        """
        profile = self.refresh_resources()
        
        if model_name not in self.model_requirements:
            raise ValueError(f"Model {model_name} not found in requirements")
        
        req = self.model_requirements[model_name]
        
        # Base settings
        settings = {
            'offload_strategy': 'auto',
            'cache_layers': 'auto',
            'ssd_cache_size_gb': 0.0,
            'memory_map_size_gb': 0.0,
            'batch_size': 1,
            'context_length': 2048
        }
        
        # Calculate based on available SSD space
        if profile.ssd_available_gb > 20.0:  # Plenty of SSD space
            # Aggressive offloading
            settings['offload_strategy'] = 'aggressive'
            settings['ssd_cache_size_gb'] = min(req.file_size_gb * 2.0, profile.ssd_available_gb * 0.2)
            settings['cache_layers'] = 'all'
            settings['context_length'] = 8192
        elif profile.ssd_available_gb > 10.0:  # Moderate SSD space
            # Balanced offloading
            settings['offload_strategy'] = 'balanced'
            settings['ssd_cache_size_gb'] = min(req.file_size_gb * 1.5, profile.ssd_available_gb * 0.15)
            settings['cache_layers'] = 'partial'
            settings['context_length'] = 4096
        elif profile.ssd_available_gb > 5.0:  # Limited SSD space
            # Conservative offloading
            settings['offload_strategy'] = 'conservative'
            settings['ssd_cache_size_gb'] = min(req.file_size_gb, profile.ssd_available_gb * 0.1)
            settings['cache_layers'] = 'minimal'
            settings['context_length'] = 2048
        else:
            # Minimal offloading - might not work well
            settings['offload_strategy'] = 'minimal'
            settings['ssd_cache_size_gb'] = 0.0
            settings['cache_layers'] = 'none'
            settings['context_length'] = 1024
        
        # Adjust based on available RAM
        if profile.available_memory_gb > 16.0:
            settings['memory_map_size_gb'] = min(8.0, profile.available_memory_gb * 0.3)
        elif profile.available_memory_gb > 8.0:
            settings['memory_map_size_gb'] = min(4.0, profile.available_memory_gb * 0.25)
        else:
            settings['memory_map_size_gb'] = min(2.0, profile.available_memory_gb * 0.2)
        
        # GPU-specific optimizations
        if profile.has_cuda and profile.gpu_memory_gb:
            if profile.gpu_memory_gb > 8.0:
                settings['gpu_layers'] = 'auto'
                settings['gpu_memory_fraction'] = 0.8
            elif profile.gpu_memory_gb > 4.0:
                settings['gpu_layers'] = 'partial'
                settings['gpu_memory_fraction'] = 0.7
            else:
                settings['gpu_layers'] = 'minimal'
                settings['gpu_memory_fraction'] = 0.6
        elif profile.has_mps:
            # MPS settings are more conservative
            settings['gpu_layers'] = 'auto'
            settings['gpu_memory_fraction'] = 0.6
        else:
            settings['gpu_layers'] = 'none'
            settings['gpu_memory_fraction'] = 0.0
        
        return settings
    
    def detect_memory_threshold_for_ollm(self, model_name: str) -> Tuple[bool, float, str]:
        """
        Detect if memory threshold is exceeded and oLLM should be activated.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Tuple[bool, float, str]: (should_activate, threshold_gb, reason)
        """
        profile = self.refresh_resources()
        
        if model_name not in self.model_requirements:
            return False, 0.0, f"Model {model_name} not found"
        
        req = self.model_requirements[model_name]
        
        # Get configured threshold
        from config import get_ollm_config
        ollm_config = get_ollm_config(model_name)
        base_threshold = ollm_config.get('ollm_memory_threshold_gb', 2.0)
        
        # Calculate dynamic threshold based on system resources
        if profile.gpu_memory_gb:
            # GPU memory threshold
            gpu_threshold = profile.gpu_memory_gb - base_threshold
            if req.estimated_memory_gb > gpu_threshold:
                return True, gpu_threshold, f"Model needs {req.estimated_memory_gb:.1f}GB, GPU threshold is {gpu_threshold:.1f}GB"
        
        # System memory threshold
        total_available = profile.available_memory_gb
        if self.enable_swap and profile.swap_available_gb > 0:
            total_available += profile.swap_available_gb * 0.5
        
        # Use 80% of available memory as threshold
        system_threshold = total_available * 0.8
        if req.estimated_memory_gb > system_threshold:
            return True, system_threshold, f"Model needs {req.estimated_memory_gb:.1f}GB, system threshold is {system_threshold:.1f}GB"
        
        # Check if model is large enough to benefit from oLLM
        if req.file_size_gb > 4.0:
            return True, 4.0, f"Large model ({req.file_size_gb:.1f}GB) benefits from oLLM memory efficiency"
        
        return False, base_threshold, "Memory threshold not exceeded"
    
    def generate_fallback_config(self, model_name: str) -> Dict[str, Any]:
        """
        Generate fallback configuration when oLLM requirements aren't met.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Dict[str, Any]: Fallback configuration for standard llama-cpp-python
        """
        profile = self.refresh_resources()
        
        # Get the most conservative configuration from existing adaptive configs
        configs = self.get_adaptive_config(model_name, force_cpu=False)
        
        if not configs:
            # Generate emergency fallback
            return {
                'n_ctx': 1024,
                'n_threads': max(1, profile.cpu_count // 4),
                'n_gpu_layers': 0,
                'use_mmap': True,
                'use_mlock': False,
                'batch_size': 1,
                'use_swap': True,
                'config_name': 'Emergency Fallback',
                'reason': 'oLLM requirements not met'
            }
        
        # Use the most conservative configuration (last in list)
        fallback_config = configs[-1]
        
        # Make it even more conservative
        conservative_config = {
            'n_ctx': min(fallback_config.n_ctx, 2048),
            'n_threads': max(1, fallback_config.n_threads // 2),
            'n_gpu_layers': min(fallback_config.n_gpu_layers, 10),
            'use_mmap': True,
            'use_mlock': False,
            'batch_size': 1,
            'use_swap': True,
            'config_name': f'Conservative Fallback ({fallback_config.config_name})',
            'reason': 'oLLM fallback configuration'
        }
        
        return conservative_config
    
    def optimize_for_concurrent_ollm(self, model_names: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Optimize resource allocation for concurrent oLLM usage.
        
        Args:
            model_names: List of model names that will run concurrently
            
        Returns:
            Dict[str, Dict[str, Any]]: Optimized configurations per model
        """
        profile = self.refresh_resources()
        
        if not model_names:
            return {}
        
        # Calculate total resource requirements
        total_memory_needed = 0.0
        total_ssd_needed = 0.0
        
        for model_name in model_names:
            if model_name in self.model_requirements:
                req = self.model_requirements[model_name]
                total_memory_needed += req.estimated_memory_gb
                total_ssd_needed += req.file_size_gb * 1.5  # Estimate SSD cache needs
        
        # Check if concurrent execution is feasible
        available_memory = profile.available_memory_gb
        if self.enable_swap:
            available_memory += profile.swap_available_gb * 0.3  # Conservative swap usage
        
        if total_memory_needed > available_memory or total_ssd_needed > profile.ssd_available_gb:
            logger.warning(f"Concurrent oLLM execution may not be feasible: "
                         f"need {total_memory_needed:.1f}GB RAM, {total_ssd_needed:.1f}GB SSD, "
                         f"have {available_memory:.1f}GB RAM, {profile.ssd_available_gb:.1f}GB SSD")
        
        # Generate optimized configurations
        configs = {}
        memory_per_model = available_memory / len(model_names)
        ssd_per_model = profile.ssd_available_gb / len(model_names)
        
        for model_name in model_names:
            base_config = self.get_ollm_config(model_name)
            
            # Adjust for concurrent usage
            optimized_config = base_config.copy()
            optimized_config.update({
                'memory_limit_gb': memory_per_model,
                'ssd_cache_limit_gb': ssd_per_model,
                'concurrent_mode': True,
                'priority': 'balanced',
                'context_length': min(base_config.get('context_length', 4096), 2048)  # Reduce context for concurrency
            })
            
            configs[model_name] = optimized_config
        
        return configs

# Global instance
_resource_manager = None

def get_resource_manager() -> AdaptiveResourceManager:
    """Get the global resource manager instance."""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = AdaptiveResourceManager()
    return _resource_manager

def create_adaptive_llm_config(model_name: str, force_cpu: bool = False) -> Dict[str, Any]:
    """
    Create an adaptive LLM configuration for a model.
    
    Args:
        model_name: Name of the model
        force_cpu: Force CPU-only mode
        
    Returns:
        Configuration dictionary for llama-cpp-python
    """
    manager = get_resource_manager()
    configs = manager.get_adaptive_config(model_name, force_cpu)
    
    if not configs:
        raise RuntimeError(f"No viable configuration found for {model_name}")
    
    # Use the first (best) configuration
    config = configs[0]
    
    logger.info(f"🎯 Selected config for {model_name}: {config.config_name}")
    logger.info(f"   Context: {config.n_ctx}, Threads: {config.n_threads}, "
               f"GPU Layers: {config.n_gpu_layers}")
    logger.info(f"   Estimated Memory: {config.estimated_memory_gb:.1f}GB")
    
    return {
        "n_ctx": config.n_ctx,
        "n_threads": config.n_threads,
        "n_gpu_layers": config.n_gpu_layers,
        "use_mmap": config.use_mmap,
        "use_mlock": config.use_mlock,
        "verbose": False,
        "_config_name": config.config_name,
        "_estimated_memory": config.estimated_memory_gb
    }