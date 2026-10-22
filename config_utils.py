"""
Configuration utilities for oLLM integration.

This module provides structured configuration classes and validation
for oLLM backend settings.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, Union, List
from pathlib import Path


@dataclass
class OLLMConfig:
    """
    Structured configuration for oLLM backend.
    
    This dataclass provides type-safe configuration management for oLLM
    with validation, default values, and serialization capabilities.
    """
    
    # Core oLLM settings
    device: str = "auto"
    logging: bool = True
    memory_threshold_gb: float = 2.0
    ssd_min_space_gb: float = 10.0
    fallback_enabled: bool = True
    
    # Model-specific overrides
    force_ollm: bool = False
    prefer_ollm: bool = False
    
    # Advanced settings
    enable_ollm: bool = True
    auto_detect: bool = True
    
    # Performance tuning
    max_memory_gb: Optional[float] = None
    cache_size_gb: Optional[float] = None
    offload_layers: Optional[int] = None
    
    # Additional oLLM parameters
    extra_params: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """
        Validate configuration parameters.
        
        Raises:
            ValueError: If configuration parameters are invalid
        """
        # Validate device
        valid_devices = ["auto", "cuda", "mps", "cpu"]
        if self.device not in valid_devices:
            raise ValueError(f"Invalid device '{self.device}'. Must be one of: {valid_devices}")
        
        # Validate memory thresholds
        if self.memory_threshold_gb < 0:
            raise ValueError("memory_threshold_gb must be non-negative")
        
        if self.ssd_min_space_gb < 0:
            raise ValueError("ssd_min_space_gb must be non-negative")
        
        # Validate optional memory settings
        if self.max_memory_gb is not None and self.max_memory_gb <= 0:
            raise ValueError("max_memory_gb must be positive if specified")
        
        if self.cache_size_gb is not None and self.cache_size_gb <= 0:
            raise ValueError("cache_size_gb must be positive if specified")
        
        if self.offload_layers is not None and self.offload_layers < 0:
            raise ValueError("offload_layers must be non-negative if specified")
        
        # Validate conflicting settings
        if self.force_ollm and not self.enable_ollm:
            raise ValueError("Cannot force oLLM when oLLM is disabled")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dict[str, Any]: Configuration as dictionary
        """
        return asdict(self)
    
    def to_json(self, indent: int = 2) -> str:
        """
        Serialize configuration to JSON string.
        
        Args:
            indent: JSON indentation level
            
        Returns:
            str: JSON representation of configuration
        """
        return json.dumps(self.to_dict(), indent=indent)
    
    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """
        Save configuration to JSON file.
        
        Args:
            file_path: Path to save configuration file
        """
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w') as f:
            f.write(self.to_json())
        
        logging.info(f"oLLM configuration saved to {file_path}")
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'OLLMConfig':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            OLLMConfig: Configuration instance
        """
        # Parameter mapping from config dict keys to dataclass fields
        param_mapping = {
            'ollm_auto_detect': 'auto_detect',
            'ollm_device': 'device',
            'ollm_logging': 'logging',
            'ollm_memory_threshold_gb': 'memory_threshold_gb',
            'ollm_ssd_min_space_gb': 'ssd_min_space_gb',
            'ollm_fallback_enabled': 'fallback_enabled',
        }
        
        # Extract known fields
        known_fields = {
            field.name for field in cls.__dataclass_fields__.values()
        }
        
        # Separate known fields from extra parameters
        known_params = {}
        extra_params = {}
        
        for key, value in config_dict.items():
            # Map parameter names if needed
            mapped_key = param_mapping.get(key, key)
            
            if mapped_key in known_fields and mapped_key != 'extra_params':
                known_params[mapped_key] = value
            elif key != 'extra_params':
                extra_params[key] = value
        
        # Handle existing extra_params
        if 'extra_params' in config_dict:
            extra_params.update(config_dict['extra_params'])
        
        # Set extra_params if any unknown parameters found
        if extra_params:
            known_params['extra_params'] = extra_params
        
        return cls(**known_params)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'OLLMConfig':
        """
        Create configuration from JSON string.
        
        Args:
            json_str: JSON configuration string
            
        Returns:
            OLLMConfig: Configuration instance
        """
        config_dict = json.loads(json_str)
        return cls.from_dict(config_dict)
    
    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> 'OLLMConfig':
        """
        Load configuration from JSON file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            OLLMConfig: Configuration instance
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        with open(file_path, 'r') as f:
            json_str = f.read()
        
        logging.info(f"oLLM configuration loaded from {file_path}")
        return cls.from_json(json_str)
    
    def merge_with(self, other: Union['OLLMConfig', Dict[str, Any]]) -> 'OLLMConfig':
        """
        Merge this configuration with another configuration.
        
        Args:
            other: Another OLLMConfig instance or dictionary to merge
            
        Returns:
            OLLMConfig: New configuration with merged values
        """
        if isinstance(other, OLLMConfig):
            other_dict = other.to_dict()
        else:
            other_dict = other
        
        # Start with current configuration
        merged_dict = self.to_dict()
        
        # Update with other configuration
        for key, value in other_dict.items():
            if key == 'extra_params' and key in merged_dict:
                # Merge extra_params dictionaries
                merged_dict[key].update(value)
            else:
                merged_dict[key] = value
        
        return self.from_dict(merged_dict)
    
    def get_ollm_inference_params(self) -> Dict[str, Any]:
        """
        Get parameters suitable for oLLM Inference initialization.
        
        Returns:
            Dict[str, Any]: Parameters for oLLM Inference
        """
        params = {
            'device': self.device,
            'logging': self.logging,
        }
        
        # Add optional parameters if specified
        if self.max_memory_gb is not None:
            params['max_memory_gb'] = self.max_memory_gb
        
        if self.cache_size_gb is not None:
            params['cache_size_gb'] = self.cache_size_gb
        
        if self.offload_layers is not None:
            params['offload_layers'] = self.offload_layers
        
        # Add any extra parameters
        params.update(self.extra_params)
        
        return params
    
    def should_use_ollm(self, model_size_gb: float, available_vram_gb: float) -> bool:
        """
        Determine if oLLM should be used based on model size and available resources.
        
        Args:
            model_size_gb: Model size in GB
            available_vram_gb: Available VRAM in GB
            
        Returns:
            bool: True if oLLM should be used
        """
        if not self.enable_ollm:
            return False
        
        if self.force_ollm:
            return True
        
        if not self.auto_detect:
            return self.prefer_ollm
        
        # Use oLLM if model exceeds available VRAM by threshold
        return model_size_gb > (available_vram_gb - self.memory_threshold_gb)
    
    def __str__(self) -> str:
        """String representation of configuration."""
        return f"OLLMConfig(device={self.device}, enable_ollm={self.enable_ollm}, memory_threshold_gb={self.memory_threshold_gb})"
    
    def __repr__(self) -> str:
        """Detailed string representation of configuration."""
        return f"OLLMConfig({self.to_dict()})"


def create_default_ollm_config() -> OLLMConfig:
    """
    Create a default oLLM configuration.
    
    Returns:
        OLLMConfig: Default configuration instance
    """
    return OLLMConfig()


def validate_ollm_config_dict(config_dict: Dict[str, Any]) -> List[str]:
    """
    Validate an oLLM configuration dictionary without creating an instance.
    
    Args:
        config_dict: Configuration dictionary to validate
        
    Returns:
        List[str]: List of validation errors (empty if valid)
    """
    errors = []
    
    try:
        # Try to create and validate configuration
        OLLMConfig.from_dict(config_dict)
    except ValueError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"Unexpected validation error: {e}")
    
    return errors


def merge_ollm_configs(base_config: Dict[str, Any], 
                      override_config: Dict[str, Any]) -> OLLMConfig:
    """
    Merge base oLLM configuration with overrides.
    
    Args:
        base_config: Base configuration dictionary
        override_config: Override configuration dictionary
        
    Returns:
        OLLMConfig: Merged configuration instance
    """
    base = OLLMConfig.from_dict(base_config)
    return base.merge_with(override_config)