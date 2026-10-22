"""
Metrics Configuration Management

This module provides configuration validation, loading, and management
for the quantitative metrics integration system.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import warnings

# Import configuration from main config
try:
    from config import (
        METRICS_CONFIG,
        METRICS_PERFORMANCE_CONFIG,
        METRICS_WEIGHTS,
        METRICS_FALLBACK_CONFIG
    )
except ImportError:
    # Fallback configuration if main config is not available
    METRICS_CONFIG = {
        "enable_code_bleu": True,
        "enable_bleu_4": True,
        "enable_rouge_l": True,
        "enable_edit_distance": True,
    }
    METRICS_PERFORMANCE_CONFIG = {
        "max_code_size_bytes": 1_000_000,
        "max_tokens_per_file": 10_000,
        "ast_parsing_timeout_seconds": 30,
        "memory_limit_mb": 100,
        "enable_parallel_calculation": False,
    }
    METRICS_WEIGHTS = {
        "code_bleu_weight": 0.4,
        "bleu_4_weight": 0.2,
        "rouge_l_weight": 0.2,
        "edit_distance_weight": 0.2,
    }
    METRICS_FALLBACK_CONFIG = {
        "fallback_to_bleu_only": True,
        "log_missing_dependencies": True,
        "fail_gracefully": True,
        "default_failed_metric_value": -1.0,
    }


@dataclass
class MetricsConfiguration:
    """
    Configuration dataclass for metrics evaluation.
    Provides type safety and validation for metric configuration options.
    """
    # Metric enablement
    enable_code_bleu: bool = True
    enable_bleu_4: bool = True
    enable_rouge_l: bool = True
    enable_edit_distance: bool = True
    
    # Performance limits
    max_code_size_bytes: int = 1_000_000
    max_tokens_per_file: int = 10_000
    ast_parsing_timeout_seconds: int = 30
    memory_limit_mb: int = 100
    enable_parallel_calculation: bool = False
    
    # Metric weights for composite scoring
    code_bleu_weight: float = 0.4
    bleu_4_weight: float = 0.2
    rouge_l_weight: float = 0.2
    edit_distance_weight: float = 0.2
    
    # Fallback configuration
    fallback_to_bleu_only: bool = True
    log_missing_dependencies: bool = True
    fail_gracefully: bool = True
    default_failed_metric_value: float = -1.0
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate configuration parameters and raise ValueError if invalid.
        
        Raises:
            ValueError: If configuration parameters are invalid
        """
        errors = []
        
        # Validate that at least one metric is enabled
        if not any([
            self.enable_code_bleu,
            self.enable_bleu_4,
            self.enable_rouge_l,
            self.enable_edit_distance
        ]):
            errors.append("At least one metric must be enabled")
        
        # Validate performance limits
        if self.max_code_size_bytes <= 0:
            errors.append("max_code_size_bytes must be positive")
        
        if self.max_tokens_per_file <= 0:
            errors.append("max_tokens_per_file must be positive")
        
        if self.ast_parsing_timeout_seconds <= 0:
            errors.append("ast_parsing_timeout_seconds must be positive")
        
        if self.memory_limit_mb <= 0:
            errors.append("memory_limit_mb must be positive")
        
        # Validate weights sum to 1.0 (approximately)
        total_weight = (
            self.code_bleu_weight +
            self.bleu_4_weight +
            self.rouge_l_weight +
            self.edit_distance_weight
        )
        
        if abs(total_weight - 1.0) > 0.01:  # Allow small floating point errors
            errors.append(f"Metric weights must sum to 1.0, got {total_weight}")
        
        # Validate individual weights are non-negative
        weights = [
            ("code_bleu_weight", self.code_bleu_weight),
            ("bleu_4_weight", self.bleu_4_weight),
            ("rouge_l_weight", self.rouge_l_weight),
            ("edit_distance_weight", self.edit_distance_weight),
        ]
        
        for weight_name, weight_value in weights:
            if weight_value < 0:
                errors.append(f"{weight_name} must be non-negative, got {weight_value}")
        
        # Validate default failed metric value
        if not isinstance(self.default_failed_metric_value, (int, float)):
            errors.append("default_failed_metric_value must be numeric")
        
        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))
    
    def get_enabled_metrics(self) -> List[str]:
        """
        Get list of enabled metric names.
        
        Returns:
            List[str]: List of enabled metric names
        """
        enabled = []
        if self.enable_code_bleu:
            enabled.append("code_bleu")
        if self.enable_bleu_4:
            enabled.append("bleu_4")
        if self.enable_rouge_l:
            enabled.append("rouge_l")
        if self.enable_edit_distance:
            enabled.append("edit_distance")
        return enabled
    
    def calculate_composite_score(self, metrics: Dict[str, float]) -> float:
        """
        Calculate weighted composite score from individual metrics.
        
        Args:
            metrics: Dictionary of metric name to score
            
        Returns:
            float: Weighted composite score
        """
        total_score = 0.0
        total_weight = 0.0
        
        # Only include metrics that are enabled and have valid scores
        if self.enable_code_bleu and "code_bleu_score" in metrics:
            score = metrics["code_bleu_score"]
            if score >= 0:  # Valid score
                total_score += score * self.code_bleu_weight
                total_weight += self.code_bleu_weight
        
        if self.enable_bleu_4 and "bleu_4_score" in metrics:
            score = metrics["bleu_4_score"]
            if score >= 0:  # Valid score
                total_score += score * self.bleu_4_weight
                total_weight += self.bleu_4_weight
        
        if self.enable_rouge_l and "rouge_l_score" in metrics:
            score = metrics["rouge_l_score"]
            if score >= 0:  # Valid score
                total_score += score * self.rouge_l_weight
                total_weight += self.rouge_l_weight
        
        if self.enable_edit_distance and "normalized_edit_distance" in metrics:
            score = metrics["normalized_edit_distance"]
            if score >= 0:  # Valid score
                total_score += score * self.edit_distance_weight
                total_weight += self.edit_distance_weight
        
        # Return weighted average if we have valid metrics
        if total_weight > 0:
            return total_score / total_weight
        else:
            return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'MetricsConfiguration':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Dictionary containing configuration values
            
        Returns:
            MetricsConfiguration: Validated configuration instance
        """
        # Filter out unknown keys
        valid_keys = set(cls.__dataclass_fields__.keys())
        filtered_dict = {k: v for k, v in config_dict.items() if k in valid_keys}
        
        return cls(**filtered_dict)


class MetricsConfigurationManager:
    """
    Manager class for loading and validating metrics configuration.
    """
    
    def __init__(self):
        """Initialize the configuration manager."""
        self.logger = logging.getLogger(__name__)
        self._config_cache: Optional[MetricsConfiguration] = None
    
    def load_default_config(self) -> MetricsConfiguration:
        """
        Load default configuration from config.py.
        
        Returns:
            MetricsConfiguration: Default configuration
        """
        try:
            config_dict = {}
            
            # Load metric enablement
            config_dict.update(METRICS_CONFIG)
            
            # Load performance configuration
            config_dict.update(METRICS_PERFORMANCE_CONFIG)
            
            # Load weights
            config_dict.update(METRICS_WEIGHTS)
            
            # Load fallback configuration
            config_dict.update(METRICS_FALLBACK_CONFIG)
            
            return MetricsConfiguration.from_dict(config_dict)
            
        except Exception as e:
            self.logger.error(f"Error loading default configuration: {e}")
            # Return minimal safe configuration
            return MetricsConfiguration()
    
    def get_config(self, override_config: Optional[Dict[str, Any]] = None) -> MetricsConfiguration:
        """
        Get configuration with optional overrides.
        
        Args:
            override_config: Optional dictionary of configuration overrides
            
        Returns:
            MetricsConfiguration: Configuration instance
        """
        if self._config_cache is None:
            self._config_cache = self.load_default_config()
        
        if override_config:
            # Create new configuration with overrides
            base_dict = self._config_cache.to_dict()
            base_dict.update(override_config)
            return MetricsConfiguration.from_dict(base_dict)
        
        return self._config_cache
    
    def validate_dependencies(self, config: MetricsConfiguration) -> Dict[str, bool]:
        """
        Check which metric dependencies are available.
        
        Args:
            config: Configuration to check dependencies for
            
        Returns:
            Dict[str, bool]: Dictionary of metric name to availability
        """
        dependencies = {}
        
        if config.enable_code_bleu:
            try:
                import tree_sitter
                dependencies["code_bleu"] = True
            except ImportError:
                dependencies["code_bleu"] = False
                if config.log_missing_dependencies:
                    self.logger.warning("tree-sitter not available for CodeBLEU calculation")
        
        if config.enable_bleu_4:
            try:
                import sacrebleu
                dependencies["bleu_4"] = True
            except ImportError:
                dependencies["bleu_4"] = False
                if config.log_missing_dependencies:
                    self.logger.warning("sacrebleu not available for BLEU-4 calculation")
        
        if config.enable_rouge_l:
            try:
                from rouge_score import rouge_scorer
                dependencies["rouge_l"] = True
            except ImportError:
                dependencies["rouge_l"] = False
                if config.log_missing_dependencies:
                    self.logger.warning("rouge-score not available for ROUGE-L calculation")
        
        if config.enable_edit_distance:
            try:
                import editdistance
                dependencies["edit_distance"] = True
            except ImportError:
                dependencies["edit_distance"] = False
                if config.log_missing_dependencies:
                    self.logger.warning("editdistance not available for edit distance calculation")
        
        return dependencies
    
    def get_recommended_config_for_environment(self) -> MetricsConfiguration:
        """
        Get recommended configuration based on available dependencies.
        
        Returns:
            MetricsConfiguration: Recommended configuration for current environment
        """
        base_config = self.load_default_config()
        dependencies = self.validate_dependencies(base_config)
        
        # Disable metrics with missing dependencies
        config_dict = base_config.to_dict()
        
        if not dependencies.get("code_bleu", True):
            config_dict["enable_code_bleu"] = False
            self.logger.info("Disabled CodeBLEU due to missing tree-sitter dependency")
        
        if not dependencies.get("bleu_4", True):
            config_dict["enable_bleu_4"] = False
            self.logger.info("Disabled BLEU-4 due to missing sacrebleu dependency")
        
        if not dependencies.get("rouge_l", True):
            config_dict["enable_rouge_l"] = False
            self.logger.info("Disabled ROUGE-L due to missing rouge-score dependency")
        
        if not dependencies.get("edit_distance", True):
            config_dict["enable_edit_distance"] = False
            self.logger.info("Disabled edit distance due to missing editdistance dependency")
        
        # Adjust weights if some metrics are disabled
        enabled_metrics = []
        if config_dict["enable_code_bleu"]:
            enabled_metrics.append("code_bleu_weight")
        if config_dict["enable_bleu_4"]:
            enabled_metrics.append("bleu_4_weight")
        if config_dict["enable_rouge_l"]:
            enabled_metrics.append("rouge_l_weight")
        if config_dict["enable_edit_distance"]:
            enabled_metrics.append("edit_distance_weight")
        
        if enabled_metrics and len(enabled_metrics) < 4:
            # Redistribute weights equally among enabled metrics
            weight_per_metric = 1.0 / len(enabled_metrics)
            
            # Reset all weights to 0
            config_dict["code_bleu_weight"] = 0.0
            config_dict["bleu_4_weight"] = 0.0
            config_dict["rouge_l_weight"] = 0.0
            config_dict["edit_distance_weight"] = 0.0
            
            # Set weights for enabled metrics
            for weight_key in enabled_metrics:
                config_dict[weight_key] = weight_per_metric
            
            self.logger.info(f"Redistributed weights equally among {len(enabled_metrics)} available metrics")
        
        return MetricsConfiguration.from_dict(config_dict)
    
    def create_example_configs(self) -> Dict[str, MetricsConfiguration]:
        """
        Create example configurations for different use cases.
        
        Returns:
            Dict[str, MetricsConfiguration]: Dictionary of example configurations
        """
        examples = {}
        
        # Fast configuration - only BLEU-4
        examples["fast"] = MetricsConfiguration(
            enable_code_bleu=False,
            enable_bleu_4=True,
            enable_rouge_l=False,
            enable_edit_distance=False,
            bleu_4_weight=1.0,
            code_bleu_weight=0.0,
            rouge_l_weight=0.0,
            edit_distance_weight=0.0,
            max_code_size_bytes=100_000,  # Smaller limit for speed
            max_tokens_per_file=1_000,
            ast_parsing_timeout_seconds=10
        )
        
        # Comprehensive configuration - all metrics
        examples["comprehensive"] = MetricsConfiguration(
            enable_code_bleu=True,
            enable_bleu_4=True,
            enable_rouge_l=True,
            enable_edit_distance=True,
            code_bleu_weight=0.4,
            bleu_4_weight=0.2,
            rouge_l_weight=0.2,
            edit_distance_weight=0.2,
            max_code_size_bytes=2_000_000,  # Larger limit for comprehensive analysis
            max_tokens_per_file=20_000,
            ast_parsing_timeout_seconds=60
        )
        
        # Syntax-focused configuration - emphasize structural metrics
        examples["syntax_focused"] = MetricsConfiguration(
            enable_code_bleu=True,
            enable_bleu_4=True,
            enable_rouge_l=False,
            enable_edit_distance=True,
            code_bleu_weight=0.6,  # Higher weight for structural similarity
            bleu_4_weight=0.2,
            rouge_l_weight=0.0,
            edit_distance_weight=0.2
        )
        
        # Memory-constrained configuration
        examples["memory_constrained"] = MetricsConfiguration(
            enable_code_bleu=False,  # Disable AST parsing to save memory
            enable_bleu_4=True,
            enable_rouge_l=True,
            enable_edit_distance=True,
            code_bleu_weight=0.0,
            bleu_4_weight=0.4,
            rouge_l_weight=0.3,
            edit_distance_weight=0.3,
            max_code_size_bytes=50_000,  # Smaller limits
            max_tokens_per_file=500,
            memory_limit_mb=50,
            ast_parsing_timeout_seconds=5
        )
        
        return examples


# Global configuration manager instance
_config_manager = MetricsConfigurationManager()

def get_metrics_config(override_config: Optional[Dict[str, Any]] = None) -> MetricsConfiguration:
    """
    Convenience function to get metrics configuration.
    
    Args:
        override_config: Optional configuration overrides
        
    Returns:
        MetricsConfiguration: Configuration instance
    """
    return _config_manager.get_config(override_config)

def get_recommended_metrics_config() -> MetricsConfiguration:
    """
    Convenience function to get recommended configuration for current environment.
    
    Returns:
        MetricsConfiguration: Recommended configuration
    """
    return _config_manager.get_recommended_config_for_environment()