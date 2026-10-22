#!/usr/bin/env python3
"""
Resource Checker for VAITP Framework

This module provides pre-execution resource checks and optimization recommendations.
It ensures the framework can adapt to available resources before starting operations.
"""

import logging
from typing import List, Dict, Tuple, Optional
from adaptive_resource_manager import get_resource_manager, AdaptiveResourceManager

logger = logging.getLogger(__name__)

class ResourceChecker:
    """Performs comprehensive resource checks before major operations."""
    
    def __init__(self):
        self.resource_manager = get_resource_manager()
    
    def pre_execution_check(self, models_to_run: List[str], 
                          operation_type: str = "model_execution") -> Tuple[bool, Dict[str, any]]:
        """
        Perform comprehensive pre-execution resource check.
        
        Args:
            models_to_run: List of models to execute
            operation_type: Type of operation (for logging)
            
        Returns:
            Tuple of (can_proceed, recommendations)
        """
        logger.info(f"🔍 Pre-execution resource check for {operation_type}")
        logger.info(f"   Models requested: {len(models_to_run)}")
        
        # Get current resource profile
        profile = self.resource_manager.refresh_resources()
        
        # Check each model
        runnable_models = []
        problematic_models = []
        
        for model_name in models_to_run:
            can_run, reason = self.resource_manager.can_run_model(model_name)
            if can_run:
                runnable_models.append(model_name)
            else:
                problematic_models.append((model_name, reason))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            profile, runnable_models, problematic_models, models_to_run
        )
        
        can_proceed = len(runnable_models) > 0
        
        # Log results
        if can_proceed:
            logger.info(f"✅ Can proceed with {len(runnable_models)}/{len(models_to_run)} models")
            if problematic_models:
                logger.warning(f"⚠️  {len(problematic_models)} models may have issues:")
                for model, reason in problematic_models:
                    logger.warning(f"   - {model}: {reason}")
        else:
            logger.error(f"❌ Cannot proceed - no models can run safely")
        
        return can_proceed, recommendations
    
    def _generate_recommendations(self, profile, runnable_models, problematic_models, 
                                original_models) -> Dict[str, any]:
        """Generate optimization recommendations."""
        recommendations = {
            "can_proceed": len(runnable_models) > 0,
            "runnable_models": runnable_models,
            "problematic_models": [model for model, _ in problematic_models],
            "optimizations": [],
            "warnings": [],
            "resource_status": "good"
        }
        
        # Memory analysis
        if profile.memory_percent > 85:
            recommendations["resource_status"] = "critical"
            recommendations["warnings"].append(
                f"Critical memory usage: {profile.memory_percent:.1f}%"
            )
            recommendations["optimizations"].append("cleanup_memory")
            recommendations["optimizations"].append("use_swap")
        elif profile.memory_percent > 70:
            recommendations["resource_status"] = "warning"
            recommendations["warnings"].append(
                f"High memory usage: {profile.memory_percent:.1f}%"
            )
            recommendations["optimizations"].append("cleanup_memory")
        
        # Model-specific recommendations
        if len(problematic_models) > 0:
            recommendations["optimizations"].append("reduce_model_set")
            
            # Check if we can run smaller models
            small_models = [m for m in runnable_models 
                          if any(size in m for size in ["1B", "1.7B"])]
            if small_models:
                recommendations["optimizations"].append("prioritize_small_models")
        
        # GPU/CPU recommendations
        if not profile.has_mps and not profile.has_cuda:
            recommendations["warnings"].append("No GPU acceleration available - using CPU only")
            recommendations["optimizations"].append("cpu_optimization")
        
        # Swap recommendations
        if profile.swap_total_gb > 0 and profile.available_memory_gb < 4:
            recommendations["optimizations"].append("enable_swap")
        
        return recommendations
    
    def apply_optimizations(self, recommendations: Dict[str, any]) -> bool:
        """
        Apply recommended optimizations.
        
        Args:
            recommendations: Recommendations from pre_execution_check
            
        Returns:
            True if optimizations were applied successfully
        """
        optimizations = recommendations.get("optimizations", [])
        
        if not optimizations:
            logger.info("✅ No optimizations needed")
            return True
        
        logger.info(f"🔧 Applying {len(optimizations)} optimizations...")
        
        success = True
        
        for optimization in optimizations:
            try:
                if optimization == "cleanup_memory":
                    logger.info("   🧹 Cleaning up memory...")
                    self.resource_manager.cleanup_memory()
                
                elif optimization == "use_swap":
                    logger.info("   💾 Enabling swap usage...")
                    # This is handled by the adaptive configs
                    pass
                
                elif optimization == "cpu_optimization":
                    logger.info("   🖥️  Optimizing for CPU-only execution...")
                    # This is handled by the adaptive configs
                    pass
                
                elif optimization == "enable_swap":
                    logger.info("   🔄 Enabling aggressive swap usage...")
                    # This is handled by the adaptive configs
                    pass
                
                else:
                    logger.info(f"   ℹ️  Optimization '{optimization}' noted for execution planning")
                
            except Exception as e:
                logger.error(f"   ❌ Failed to apply optimization '{optimization}': {e}")
                success = False
        
        return success
    
    def get_execution_plan(self, models_to_run: List[str]) -> Dict[str, any]:
        """
        Generate an optimized execution plan.
        
        Args:
            models_to_run: List of models to execute
            
        Returns:
            Execution plan with optimized order and configurations
        """
        logger.info("📋 Generating optimized execution plan...")
        
        # Pre-execution check
        can_proceed, recommendations = self.pre_execution_check(models_to_run, "execution_planning")
        
        if not can_proceed:
            return {
                "can_execute": False,
                "reason": "Insufficient resources for any models",
                "recommendations": recommendations
            }
        
        # Get optimized model order
        optimized_order = self.resource_manager.optimize_model_order(
            recommendations["runnable_models"]
        )
        
        # Generate execution plan
        execution_plan = {
            "can_execute": True,
            "total_models": len(models_to_run),
            "executable_models": len(optimized_order),
            "skipped_models": len(models_to_run) - len(optimized_order),
            "execution_order": optimized_order,
            "skipped": recommendations["problematic_models"],
            "recommendations": recommendations,
            "estimated_duration": self._estimate_duration(optimized_order),
            "resource_requirements": self._get_resource_requirements(optimized_order)
        }
        
        # Log execution plan
        logger.info(f"📊 Execution Plan Summary:")
        logger.info(f"   Total models: {execution_plan['total_models']}")
        logger.info(f"   Executable: {execution_plan['executable_models']}")
        logger.info(f"   Skipped: {execution_plan['skipped_models']}")
        logger.info(f"   Estimated duration: {execution_plan['estimated_duration']:.1f} minutes")
        
        return execution_plan
    
    def _estimate_duration(self, models: List[str]) -> float:
        """Estimate execution duration in minutes."""
        # Base time per model (rough estimate)
        base_time_per_model = 5.0  # minutes
        
        # Adjust based on model sizes
        total_time = 0
        for model in models:
            if model in self.resource_manager.model_requirements:
                req = self.resource_manager.model_requirements[model]
                # Larger models take longer
                size_multiplier = 1 + (req.file_size_gb / 5.0)  # Scale with size
                total_time += base_time_per_model * size_multiplier
            else:
                total_time += base_time_per_model
        
        return total_time
    
    def _get_resource_requirements(self, models: List[str]) -> Dict[str, float]:
        """Get total resource requirements for models."""
        total_memory = 0
        max_memory = 0
        
        for model in models:
            if model in self.resource_manager.model_requirements:
                req = self.resource_manager.model_requirements[model]
                total_memory += req.estimated_memory_gb
                max_memory = max(max_memory, req.estimated_memory_gb)
        
        return {
            "total_memory_gb": total_memory,
            "peak_memory_gb": max_memory,
            "models_count": len(models)
        }

# Global instance
_resource_checker = None

def get_resource_checker() -> ResourceChecker:
    """Get the global resource checker instance."""
    global _resource_checker
    if _resource_checker is None:
        _resource_checker = ResourceChecker()
    return _resource_checker

def check_resources_before_execution(models_to_run: List[str], 
                                   operation_type: str = "model_execution") -> bool:
    """
    Convenience function to check resources before execution.
    
    Args:
        models_to_run: List of models to execute
        operation_type: Type of operation
        
    Returns:
        True if execution can proceed
    """
    checker = get_resource_checker()
    can_proceed, recommendations = checker.pre_execution_check(models_to_run, operation_type)
    
    if can_proceed:
        # Apply optimizations
        checker.apply_optimizations(recommendations)
    
    return can_proceed

def get_optimized_execution_plan(models_to_run: List[str]) -> Dict[str, any]:
    """
    Get an optimized execution plan for the given models.
    
    Args:
        models_to_run: List of models to execute
        
    Returns:
        Execution plan dictionary
    """
    checker = get_resource_checker()
    return checker.get_execution_plan(models_to_run)