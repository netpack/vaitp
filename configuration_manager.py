"""
Configuration Management System for VAITP Platform

This module provides configuration loading, validation, and metadata management
for experiment reproducibility and configuration-driven execution.
"""

import yaml
import json
import os
import argparse
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import logging

from config import CODER_MODELS, REASONING_MODELS

from rich.console import Console
console = Console()


@dataclass
class ExperimentMetadata:
    """Metadata structure for experiment tracking and reproducibility."""
    experiment_name: str
    run_description: str
    start_time: str
    config_used: Dict[str, Any]
    system_info: Dict[str, Any]
    end_time: Optional[str] = None
    total_duration: Optional[float] = None
    results_summary: Optional[Dict[str, Any]] = None


class ConfigurationManager:
    """
    Manages YAML configuration loading, validation, and experiment metadata.
    
    Provides configuration-driven experiment execution with command-line overrides
    and comprehensive metadata preservation for reproducibility.
    """
    
    def __init__(self):
        """Initialize the configuration manager with validation schema."""
        self.config_schema = self._create_config_schema()
        self.logger = logging.getLogger(__name__)
    
    def _create_config_schema(self) -> Dict[str, Any]:
        """Define the comprehensive configuration schema for validation."""
        return {
            # Core required fields for all experiments
            'required_fields': [
                'experiment_name',
                'phase'
            ],
            
            # Optional fields with default values
            'optional_fields': [
                'run_description',
                'stage',
                'reasoning_model',
                'coders_to_run',
                'strategies_to_run',
                'num_gpus',
                'input_dataset_dir',
                'expected_dir',
                'export',
                'timeout_per_model',
                'max_retries',
                'save_excel',
                'excel_per_model',
                'input_pickle',
                'phase3_test_all',
                'intended_vulnerability',
                'trace_diagram',
                'trace_detail_level',
            ],
            
            # Valid values for enumerated fields
            'valid_phases': [1, 2, 3, 'full', 'promote', 'reanalyze', 'export'],
            'valid_stages': ['generate', 'analyze', 'evaluate', 'all'],
            'valid_reasoning_models': list(REASONING_MODELS.keys()),
            'valid_coder_models': list(CODER_MODELS.keys()) + ['all'],
            'valid_strategies': ['DIRECT_ONLY', 'DIRECT_RAG', 'META_ONLY', 'META_RAG', 'FEW_SHOT', 'all'],
            
            # Phase-specific required fields
            'phase_requirements': {
                1: ['input_dataset_dir'],  # Phase 1 requires input directory
                2: [],  # Phase 2 can work with existing plans
                'reanalyze': ['input_pickle'],  # Reanalyze requires pickle file
                'export': []  # Export works with database
            },
            
            # Phase-specific optional fields that are commonly used
            'phase_recommendations': {
                1: ['reasoning_model'],
                2: ['coders_to_run', 'strategies_to_run', 'stage', 'expected_dir'],
                'reanalyze': ['expected_dir'],
                'export': ['save_excel', 'excel_per_model']
            },
            
            # Field types for validation
            'field_types': {
                'experiment_name': str,
                'run_description': str,
                'phase': (int, str),
                'stage': str,
                'reasoning_model': str,
                'coders_to_run': (list, str),
                'strategies_to_run': (list, str),
                'num_gpus': int,
                'input_dataset_dir': str,
                'expected_dir': str,
                'timeout_per_model': int,
                'max_retries': int,
                'save_excel': bool,
                'excel_per_model': bool,
                'input_pickle': str,
                'phase3_test_all': bool,
                'intended_vulnerability': (dict, str),
                'trace_diagram': bool,
                'trace_detail_level': str,
            },
            
            # Default values for optional fields
            'defaults': {
                'run_description': 'No description provided',
                'stage': 'all',
                'reasoning_model': 'llama-3.1-8b',
                'coders_to_run': ['all'],
                'strategies_to_run': ['all'],
                'num_gpus': None,  # Auto-detect
                'timeout_per_model': 3600,  # 1 hour default
                'max_retries': 3,
                'save_excel': False,
                'excel_per_model': False,
                'trace_diagram': False,
                'trace_detail_level': 'standard',
            },
            
            # Validation constraints
            'constraints': {
                'experiment_name': {
                    'min_length': 1,
                    'max_length': 100,
                    'pattern': r'^[a-zA-Z0-9_\-\s]+$'  # Alphanumeric, underscore, dash, space
                },
                'num_gpus': {
                    'min_value': 1,
                    'max_value': 16  # Reasonable upper limit
                },
                'timeout_per_model': {
                    'min_value': 60,  # At least 1 minute
                    'max_value': 86400  # At most 24 hours
                },
                'max_retries': {
                    'min_value': 0,
                    'max_value': 10
                }
            }
        }
    
    def load_config(self, config_path: str, args: argparse.Namespace) -> Dict[str, Any]:
        """
        Load YAML configuration and merge with command-line overrides.
        
        Command-line arguments take precedence over config file values.
        
        Args:
            config_path: Path to YAML configuration file
            args: Parsed command-line arguments
            
        Returns:
            Merged configuration dictionary
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file has invalid YAML syntax
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML syntax in {config_path}: {e}")
        
        # Merge command-line arguments (they take precedence)
        config = self._normalize_yaml_keys(config)
        config = self._merge_args_with_config(config, args)
        
        # Add runtime metadata
        config['_metadata'] = {
            'config_file_path': config_path,
            'loaded_at': datetime.now().isoformat(),
            'merged_from_args': True
        }
        
        return config
    
    @staticmethod
    def _normalize_yaml_keys(config: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize common YAML key aliases to their canonical config names.
        
        Users may write 'strategy: DIRECT_RAG' (singular) or
        'strategies_to_run: [DIRECT_RAG]' (canonical). This ensures both work.
        """
        aliases = {
            'strategy': 'strategies_to_run',
            'strategies': 'strategies_to_run',
            'coder': 'coders_to_run',
            'coders': 'coders_to_run',
            'model': 'reasoning_model',
        }
        normalized = {}
        for key, value in config.items():
            canonical = aliases.get(key, key)
            # Don't overwrite if the canonical key is already set
            if canonical in normalized and key in aliases:
                continue
            # Wrap single string values in a list for list-type fields
            if canonical in ('strategies_to_run', 'coders_to_run') and isinstance(value, str):
                value = [value]
            normalized[canonical] = value
        return normalized

    def _merge_args_with_config(self, config: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
        """
        Merge command-line arguments with configuration file.
        
        Command-line arguments override config file values.
        """
        # Create a copy to avoid modifying the original
        merged_config = config.copy()
        
        # Map command-line arguments to config keys
        arg_mapping = {
            'phase': 'phase',
            'model': 'reasoning_model', 
            'coder': 'coders_to_run',
            'strategy': 'strategies_to_run',
            'stage': 'stage',
            'save_excel': 'save_excel',
            'excel_per_model': 'excel_per_model',
            'expected_dir': 'expected_dir',
            'input_pickle': 'input_pickle',
            'num_gpus': 'num_gpus',
            'path': 'input_dataset_dir',
            'trace_diagram': 'trace_diagram',
            'trace_detail_level': 'trace_detail_level',
        }
        
        # Override config with command-line arguments (only if explicitly provided)
        # When using --config, we don't want argparse defaults to override config values
        for arg_name, config_key in arg_mapping.items():
            arg_value = getattr(args, arg_name, None)
            # Only override if the argument was explicitly provided and differs from common defaults
            if arg_value is not None:
                # Skip overriding if it's a common default value that would override config
                if arg_name in ['coder', 'strategy'] and arg_value == ['all']:
                    # Don't override config with default 'all' values
                    continue
                # Don't let store_true defaults (False) override YAML true values
                if arg_name in ['trace_diagram', 'save_excel', 'excel_per_model'] \
                        and arg_value is False and config_key in merged_config:
                    continue
                # Don't let None-string defaults override YAML values
                if arg_name in ['trace_detail_level'] \
                        and arg_value is None:
                    continue
                merged_config[config_key] = arg_value
        
        return merged_config
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Comprehensive configuration validation against schema and system constraints.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if valid
            
        Raises:
            ValueError: If configuration is invalid with detailed error message
        """
        errors = []
        warnings = []
        
        # Apply defaults for missing optional fields
        self._apply_defaults(config)
        
        # Check required fields
        for field in self.config_schema['required_fields']:
            if field not in config or config[field] is None:
                errors.append(f"Missing required field: '{field}'")
        
        # Validate field types
        for field, expected_types in self.config_schema['field_types'].items():
            if field in config and config[field] is not None:
                if not isinstance(config[field], expected_types):
                    errors.append(f"Field '{field}' must be of type {expected_types}, got {type(config[field])}")
        
        # Validate phase and phase-specific requirements
        if 'phase' in config:
            phase = self._normalize_phase(config)
            config['phase'] = phase
            
            if phase not in self.config_schema['valid_phases']:
                errors.append(f"Invalid phase '{phase}'. Must be one of: {self.config_schema['valid_phases']}")
            else:
                # Check phase-specific required fields
                phase_required = self.config_schema['phase_requirements'].get(phase, [])
                for field in phase_required:
                    if field not in config or not config[field]:
                        errors.append(f"Phase {phase} requires field: '{field}'")
                
                # Check phase-specific recommendations
                phase_recommended = self.config_schema['phase_recommendations'].get(phase, [])
                for field in phase_recommended:
                    if field not in config or not config[field]:
                        warnings.append(f"Phase {phase} commonly uses field: '{field}' (consider adding it)")
        
        # Validate enumerated fields
        self._validate_enumerated_fields(config, errors)
        
        # Validate strategies (was missing from the call chain)
        self._validate_strategies(config, errors)
        
        # Validate model names against available models
        self._validate_model_names(config, errors)
        
        # Validate paths exist
        self._validate_paths(config, errors)
        
        # Validate numeric constraints
        self._validate_numeric_constraints(config, errors)
        
        # Validate experiment name pattern
        self._validate_experiment_name(config, errors)
        
        # Validate export configuration
        self._validate_export_config(config, errors)
        
        # Validate phase-specific logic consistency
        self._validate_phase_consistency(config, errors)
        
        # Log warnings
        for warning in warnings:
            self.logger.warning(warning)
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors)
            error_msg += "\n\nFor help with configuration, run with --help or check the documentation."
            raise ValueError(error_msg)
        
        self.logger.info("Configuration validation passed")
        return True
    
    def _apply_defaults(self, config: Dict[str, Any]) -> None:
        """Apply default values for missing optional fields."""
        for field, default_value in self.config_schema['defaults'].items():
            if field not in config or config[field] is None:
                config[field] = default_value
    
    def _normalize_phase(self, config: Dict[str, Any]) -> Any:
        """Normalize phase value (convert string numbers to integers)."""
        phase = config['phase']
        if isinstance(phase, str) and phase.isdigit():
            return int(phase)
        return phase
    
    def _validate_enumerated_fields(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate fields with enumerated valid values."""
        enum_validations = [
            ('stage', 'valid_stages'),
        ]
        
        # Only validate reasoning_model against local models if not using Vertex
        if not config.get('vertex'):
            enum_validations.append(('reasoning_model', 'valid_reasoning_models'))
        
        for field, valid_key in enum_validations:
            if field in config and config[field]:
                valid_values = self.config_schema[valid_key]
                if config[field] not in valid_values:
                    errors.append(f"Invalid {field} '{config[field]}'. Must be one of: {valid_values}")
    
    def _validate_model_names(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate model names against CODER_MODELS and REASONING_MODELS."""
        # Skip model validation for Vertex AI configs — model names are remote IDs
        if config.get('vertex'):
            return
        
        # Validate coder models
        if 'coders_to_run' in config and config['coders_to_run']:
            coders = config['coders_to_run']
            if isinstance(coders, str):
                coders = [coders]
            
            valid_coders = self.config_schema['valid_coder_models']
            for coder in coders:
                if coder not in valid_coders:
                    available_models = [m for m in valid_coders if m != 'all']
                    errors.append(f"Invalid coder model '{coder}'. Available models: {available_models}")
                    
                # Check if model file exists (except for 'all')
                if coder != 'all' and coder in CODER_MODELS:
                    model_path = CODER_MODELS[coder]['path']
                    if not os.path.exists(model_path):
                        errors.append(f"Model file not found for '{coder}': {model_path}")
                        errors.append(f"  Suggestion: Check that the model is downloaded and the path in config.py is correct")
        
        # Validate reasoning model file exists
        if 'reasoning_model' in config and config['reasoning_model']:
            model_name = config['reasoning_model']
            if model_name not in REASONING_MODELS:
                available_reasoning = list(REASONING_MODELS.keys())
                errors.append(f"Invalid reasoning model '{model_name}'. Available models: {available_reasoning}")
            else:
                model_path = REASONING_MODELS[model_name]['path']
                if not os.path.exists(model_path):
                    errors.append(f"Reasoning model file not found for '{model_name}': {model_path}")
                    errors.append(f"  Suggestion: Check that the model is downloaded and the path in config.py is correct")
    
    def _validate_paths(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate that specified paths exist and are of correct type."""
        path_validations = {
            'input_dataset_dir': {
                'required_type': 'directory',
                'description': 'directory containing injectable Python files',
                'suggestion': 'Create the directory and add .py files, or check the path is correct'
            },
            'expected_dir': {
                'required_type': 'directory', 
                'description': 'directory containing expected/fixed Python files',
                'suggestion': 'This should mirror the structure of input_dataset_dir with fixed versions'
            },
            'input_pickle': {
                'required_type': 'file',
                'description': '.pkl file from previous Phase 1 run',
                'suggestion': 'Run Phase 1 first to generate the pickle file, or check the path is correct',
                'extension': '.pkl'
            }
        }
        
        for field, validation in path_validations.items():
            if field in config and config[field]:
                path = config[field]
                
                if not os.path.exists(path):
                    errors.append(f"Path does not exist for '{field}': {path}")
                    errors.append(f"  Expected: {validation['description']}")
                    errors.append(f"  Suggestion: {validation['suggestion']}")
                    continue
                
                # Check if it's the right type (file vs directory)
                if validation['required_type'] == 'directory' and not os.path.isdir(path):
                    errors.append(f"'{field}' must be a directory, but found file: {path}")
                elif validation['required_type'] == 'file' and not os.path.isfile(path):
                    errors.append(f"'{field}' must be a file, but found directory: {path}")
                
                # Check file extension if specified
                if 'extension' in validation and not path.endswith(validation['extension']):
                    errors.append(f"'{field}' must have extension '{validation['extension']}': {path}")
                
                # Additional content validation for directories
                if field == 'input_dataset_dir' and os.path.isdir(path):
                    py_files = [f for f in os.listdir(path) if f.endswith('.py')]
                    # For Phase 3, .py files are in vulnerable/ and injectable/ subdirs
                    if not py_files:
                        vuln_dir = os.path.join(path, 'vulnerable')
                        if os.path.isdir(vuln_dir):
                            py_files = [f for f in os.listdir(vuln_dir) if f.endswith('.py')]
                    if not py_files:
                        errors.append(f"Directory '{field}' contains no Python files: {path}")
                        errors.append(f"  Suggestion: Add .py files to the directory or check the path")
    
    def _validate_numeric_constraints(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate numeric fields against constraints."""
        for field, constraints in self.config_schema['constraints'].items():
            if field in config and config[field] is not None:
                value = config[field]
                
                # Convert to appropriate type
                if field in ['num_gpus', 'timeout_per_model', 'max_retries']:
                    try:
                        value = int(value)
                        config[field] = value
                    except (ValueError, TypeError):
                        errors.append(f"'{field}' must be a valid integer, got: {config[field]}")
                        continue
                
                # Check min/max values
                if 'min_value' in constraints and value < constraints['min_value']:
                    errors.append(f"'{field}' must be at least {constraints['min_value']}, got: {value}")
                if 'max_value' in constraints and value > constraints['max_value']:
                    errors.append(f"'{field}' must be at most {constraints['max_value']}, got: {value}")
    
    def _validate_experiment_name(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate experiment name against pattern and length constraints."""
        if 'experiment_name' in config and config['experiment_name']:
            name = config['experiment_name']
            constraints = self.config_schema['constraints']['experiment_name']
            
            if len(name) < constraints['min_length']:
                errors.append(f"Experiment name must be at least {constraints['min_length']} character(s)")
            if len(name) > constraints['max_length']:
                errors.append(f"Experiment name must be at most {constraints['max_length']} characters")
            
            import re
            if not re.match(constraints['pattern'], name):
                errors.append("Experiment name can only contain letters, numbers, underscores, dashes, and spaces")
    
    def _validate_export_config(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate export-related configuration."""
        if 'export' in config and isinstance(config['export'], dict):
            export_config = config['export']
            valid_export_fields = ['save_csv', 'save_excel', 'excel_per_model']
            
            for field in export_config:
                if field not in valid_export_fields:
                    errors.append(f"Invalid export field '{field}'. Must be one of: {valid_export_fields}")
                elif not isinstance(export_config[field], bool):
                    errors.append(f"Export field '{field}' must be boolean, got: {type(export_config[field])}")
    
    def _validate_strategies(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate strategy names."""
        if 'strategies_to_run' in config and config['strategies_to_run']:
            strategies = config['strategies_to_run']
            if isinstance(strategies, str):
                strategies = [strategies]
            
            valid_strategies = self.config_schema['valid_strategies']
            for strategy in strategies:
                if strategy not in valid_strategies:
                    errors.append(f"Invalid strategy '{strategy}'. Must be one of: {valid_strategies}")
    
    def get_validation_schema(self) -> Dict[str, Any]:
        """
        Return the complete validation schema for external tools and documentation.
        
        Returns:
            Complete configuration schema with all validation rules
        """
        return self.config_schema.copy()
    
    def validate_config_file_syntax(self, config_path: str) -> bool:
        """
        Validate YAML file syntax without loading the full configuration.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            True if syntax is valid
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file has invalid YAML syntax with detailed error info
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            return True
        except yaml.YAMLError as e:
            # Enhance error message with line/column information if available
            error_msg = f"Invalid YAML syntax in {config_path}"
            if hasattr(e, 'problem_mark'):
                mark = e.problem_mark
                error_msg += f" at line {mark.line + 1}, column {mark.column + 1}"
            if hasattr(e, 'problem'):
                error_msg += f": {e.problem}"
            raise yaml.YAMLError(error_msg)
    
    def get_helpful_error_message(self, error_type: str, field: str = None, value: Any = None) -> str:
        """
        Generate helpful error messages with suggestions for common configuration issues.
        
        Args:
            error_type: Type of error (missing_field, invalid_value, etc.)
            field: Field name that caused the error
            value: Invalid value that was provided
            
        Returns:
            Detailed error message with suggestions
        """
        base_messages = {
            'missing_field': f"Required field '{field}' is missing.",
            'invalid_value': f"Invalid value '{value}' for field '{field}'.",
            'invalid_type': f"Field '{field}' has wrong type. Expected {self.config_schema['field_types'].get(field, 'unknown')}, got {type(value).__name__}.",
            'path_not_found': f"Path '{value}' for field '{field}' does not exist.",
            'model_not_found': f"Model '{value}' for field '{field}' is not available.",
            'invalid_phase': f"Phase '{value}' is not supported."
        }
        
        suggestions = {
            'missing_field': {
                'experiment_name': "Add a descriptive name like 'experiment_name: my_vulnerability_test'",
                'phase': "Specify which phase to run: 'phase: 1' (generate), 'phase: 2' (execute), 'phase: reanalyze', or 'phase: export'",
                'input_dataset_dir': "Provide path to injectable code: 'input_dataset_dir: /path/to/injectable'",
                'coders_to_run': "Specify models to test: 'coders_to_run: [\"Llama-3.1-8B-Base\"]' or 'coders_to_run: [\"all\"]'"
            },
            'invalid_value': {
                'phase': f"Valid phases are: {self.config_schema['valid_phases']}",
                'reasoning_model': f"Available reasoning models: {self.config_schema['valid_reasoning_models']}",
                'coders_to_run': f"Available coder models: {[m for m in self.config_schema['valid_coder_models'] if m != 'all']}",
                'strategies_to_run': f"Available strategies: {[s for s in self.config_schema['valid_strategies'] if s != 'all']}"
            },
            'path_not_found': {
                'input_dataset_dir': "Ensure the directory exists and contains injectable Python files",
                'expected_dir': "This should point to the directory with expected/fixed code versions",
                'input_pickle': "This should be a .pkl file from a previous Phase 1 run"
            },
            'model_not_found': "Check that the model file exists at the specified path in config.py"
        }
        
        message = base_messages.get(error_type, f"Configuration error in field '{field}'")
        
        if error_type in suggestions and field in suggestions[error_type]:
            message += f"\nSuggestion: {suggestions[error_type][field]}"
        elif error_type in suggestions and error_type != 'missing_field':
            general_suggestion = suggestions[error_type].get('general', suggestions[error_type].get(list(suggestions[error_type].keys())[0]))
            if general_suggestion:
                message += f"\nSuggestion: {general_suggestion}"
        
        return message
    
    def _validate_phase_consistency(self, config: Dict[str, Any], errors: List[str]) -> None:
        """Validate that configuration is consistent for the specified phase."""
        if 'phase' not in config:
            return
            
        phase = config['phase']
        
        # Phase 1 specific validations
        if phase == 1:
            if not config.get('input_dataset_dir'):
                errors.append(self.get_helpful_error_message('missing_field', 'input_dataset_dir'))
            if config.get('input_pickle'):
                errors.append("Phase 1 should not use 'input_pickle' - this is for reanalysis phase")
                
        # Phase 2 specific validations  
        elif phase == 2:
            if config.get('stage') == 'generate':
                errors.append("Phase 2 with stage 'generate' is unusual - consider using Phase 1 instead")
            if not config.get('coders_to_run'):
                errors.append("Phase 2 typically requires 'coders_to_run' to specify which models to test")
                
        # Reanalyze phase specific validations
        elif phase == 'reanalyze':
            if not config.get('input_pickle'):
                errors.append(self.get_helpful_error_message('missing_field', 'input_pickle'))
            if config.get('input_dataset_dir') and not config.get('expected_dir'):
                errors.append("Reanalysis with new dataset typically requires 'expected_dir' for comparison")
                
        # Export phase specific validations
        elif phase == 'export':
            export_config = config.get('export', {})
            if not any([export_config.get('save_csv'), export_config.get('save_excel'), export_config.get('excel_per_model')]):
                errors.append("Export phase should specify at least one export format (save_csv, save_excel, or excel_per_model)")
    
    def create_example_config(self, phase: int, experiment_type: str = "basic") -> Dict[str, Any]:
        """
        Create example configuration for documentation and migration tools.
        
        Args:
            phase: Phase number (1, 2, etc.)
            experiment_type: Type of experiment (basic, advanced, parallel)
            
        Returns:
            Example configuration dictionary
        """
        base_config = {
            'experiment_name': f'example_phase_{phase}_experiment',
            'run_description': f'Example Phase {phase} experiment configuration',
            'phase': phase
        }
        
        if phase == 1:
            base_config.update({
                'input_dataset_dir': 'vaitp_dataset/injectable',
                'reasoning_model': 'llama-3.1-8b',
                'stage': 'generate'
            })
            
        elif phase == 2:
            base_config.update({
                'coders_to_run': ['Llama-3.1-8B-Base', 'Qwen-3-8B-Base'],
                'strategies_to_run': ['DIRECT_ONLY', 'DIRECT_RAG'],
                'stage': 'all',
                'expected_dir': 'vaitp_dataset/expected'
            })
            
            if experiment_type == "parallel":
                base_config['num_gpus'] = 2
                
        elif phase == 'export':
            base_config.update({
                'export': {
                    'save_excel': True,
                    'excel_per_model': True
                }
            })
            
        return base_config
    
    def validate_phase_config(self, config: Dict[str, Any], phase: Any) -> bool:
        """
        Validate configuration for a specific phase with detailed error messages.
        
        Args:
            config: Configuration dictionary
            phase: Phase to validate for (1, 2, 'reanalyze', 'export')
            
        Returns:
            True if valid for the phase
            
        Raises:
            ValueError: If configuration is invalid for the specified phase
        """
        errors = []
        warnings = []
        
        # Normalize phase
        if isinstance(phase, str) and phase.isdigit():
            phase = int(phase)
        
        # Phase-specific validation
        if phase == 1:
            # Phase 1 requires input dataset directory
            if not config.get('input_dataset_dir'):
                errors.append("Phase 1 requires 'input_dataset_dir' to specify the directory containing injectable Python files")
            
            # Phase 1 should have a reasoning model
            if not config.get('reasoning_model'):
                warnings.append("Phase 1 typically uses 'reasoning_model' for plan generation")
                
        elif phase == 2:
            # Phase 2 typically needs coder models
            if not config.get('coders_to_run'):
                warnings.append("Phase 2 typically requires 'coders_to_run' to specify which models to test")
            
            # Phase 2 benefits from strategies
            if not config.get('strategies_to_run'):
                warnings.append("Phase 2 typically uses 'strategies_to_run' to specify prompting strategies")
            
            # Phase 2 benefits from expected directory for evaluation
            if not config.get('expected_dir'):
                warnings.append("Phase 2 benefits from 'expected_dir' for code similarity evaluation")
                
        elif phase == 'reanalyze':
            # Reanalyze requires input pickle
            if not config.get('input_pickle'):
                errors.append("Reanalyze phase requires 'input_pickle' pointing to a .pkl file from previous runs")
            
            # Validate pickle file exists and has correct extension
            if config.get('input_pickle'):
                pickle_path = config['input_pickle']
                if not pickle_path.endswith('.pkl'):
                    errors.append(f"'input_pickle' must be a .pkl file, got: {pickle_path}")
                if not os.path.exists(pickle_path):
                    errors.append(f"Pickle file does not exist: {pickle_path}")
                    
        elif phase == 'export':
            # Export phase should specify at least one export format
            export_config = config.get('export', {})
            has_export_format = any([
                export_config.get('save_csv'),
                export_config.get('save_excel'), 
                export_config.get('excel_per_model'),
                config.get('save_excel'),  # Legacy format
                config.get('excel_per_model')  # Legacy format
            ])
            
            if not has_export_format:
                warnings.append("Export phase should specify at least one export format (save_excel, excel_per_model, etc.)")

        elif phase == 3:
            pass  # Phase 3 has its own validation in run_phase3.py

        elif phase == 'full':
            # Full pipeline requires input dataset directory (for Phase 1)
            if not config.get('input_dataset_dir'):
                errors.append("Full pipeline requires 'input_dataset_dir' for Phase 1 plan generation")

        elif phase == 'promote':
            pass  # Promote just needs the prompts directory which is derived from model/experiment
        
        # Log warnings
        for warning in warnings:
            self.logger.warning(f"Phase {phase} configuration: {warning}")
        
        # Raise errors
        if errors:
            error_msg = f"Configuration validation failed for Phase {phase}:\n"
            error_msg += "\n".join(f"  - {error}" for error in errors)
            raise ValueError(error_msg)
        
        return True
    
    def save_experiment_metadata(self, config: Dict[str, Any], results_dir: str, 
                                execution_stats: Optional[Dict[str, Any]] = None) -> str:
        """
        Save comprehensive experiment configuration and metadata for reproducibility tracking.
        
        Args:
            config: Final merged configuration
            results_dir: Directory to save metadata files
            execution_stats: Optional execution statistics (duration, success rates, etc.)
            
        Returns:
            Path to saved metadata file
        """
        # Ensure results directory exists
        os.makedirs(results_dir, exist_ok=True)
        
        # Create comprehensive experiment metadata
        metadata = ExperimentMetadata(
            experiment_name=config.get('experiment_name', 'unnamed_experiment'),
            run_description=config.get('run_description', 'No description provided'),
            start_time=datetime.now().isoformat(),
            config_used=config,
            system_info=self._get_system_info()
        )
        
        # Add execution statistics if provided
        if execution_stats:
            metadata.end_time = execution_stats.get('end_time')
            metadata.total_duration = execution_stats.get('total_duration')
            metadata.results_summary = execution_stats.get('results_summary')
        
        # Save metadata as JSON with enhanced information
        metadata_dict = asdict(metadata)
        
        # Add additional metadata not in the dataclass
        metadata_dict['metadata_version'] = '1.0'
        metadata_dict['framework_version'] = 'VAITP-Platform-v2.0'
        metadata_dict['config_file_used'] = config.get('_metadata', {}).get('config_file_path')
        metadata_dict['command_line_overrides'] = config.get('_metadata', {}).get('merged_from_args', False)
        
        # Add git information if available
        try:
            import subprocess
            git_info = {}
            try:
                git_info['commit_hash'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], 
                                                                stderr=subprocess.DEVNULL).decode().strip()
                git_info['branch'] = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
                                                           stderr=subprocess.DEVNULL).decode().strip()
                git_info['is_dirty'] = len(subprocess.check_output(['git', 'status', '--porcelain'], 
                                                                 stderr=subprocess.DEVNULL)) > 0
            except subprocess.CalledProcessError:
                git_info['error'] = 'Not a git repository or git not available'
            metadata_dict['git_info'] = git_info
        except ImportError:
            metadata_dict['git_info'] = {'error': 'subprocess module not available'}
        
        metadata_path = os.path.join(results_dir, 'experiment_metadata.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata_dict, f, indent=2, ensure_ascii=False)
        
        # Save configuration as YAML for easy editing/reuse
        config_path = os.path.join(results_dir, 'experiment_config.yaml')
        # Create a clean config without internal metadata for reuse
        clean_config = {k: v for k, v in config.items() if not k.startswith('_')}
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(clean_config, f, default_flow_style=False, allow_unicode=True)
        
        # Save a detailed execution environment snapshot
        env_path = os.path.join(results_dir, 'execution_environment.json')
        env_info = self._get_detailed_environment_info()
        with open(env_path, 'w', encoding='utf-8') as f:
            json.dump(env_info, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Experiment metadata saved to: {metadata_path}")
        self.logger.info(f"Experiment configuration saved to: {config_path}")
        self.logger.info(f"Execution environment saved to: {env_path}")
        
        return metadata_path
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Collect system information for metadata."""
        import platform
        import psutil
        
        try:
            # Try to get GPU info
            gpu_info = "Not available"
            try:
                import torch
                if torch.cuda.is_available():
                    gpu_count = torch.cuda.device_count()
                    gpu_names = [torch.cuda.get_device_name(i) for i in range(gpu_count)]
                    gpu_info = f"{gpu_count} GPUs: {', '.join(gpu_names)}"
                else:
                    gpu_info = "CUDA not available"
            except ImportError:
                gpu_info = "PyTorch not available"
            
            return {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'gpu_info': gpu_info,
                'hostname': platform.node()
            }
        except Exception as e:
            self.logger.warning(f"Could not collect complete system info: {e}")
            return {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'error': str(e)
            }
    
    def _get_detailed_environment_info(self) -> Dict[str, Any]:
        """Collect detailed environment information for reproducibility."""
        import platform
        import sys
        
        env_info = {
            'python': {
                'version': platform.python_version(),
                'implementation': platform.python_implementation(),
                'executable': sys.executable,
                'path': sys.path[:5]  # First 5 entries to avoid too much data
            },
            'system': {
                'platform': platform.platform(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'architecture': platform.architecture(),
                'hostname': platform.node()
            },
            'environment_variables': {
                'CUDA_VISIBLE_DEVICES': os.environ.get('CUDA_VISIBLE_DEVICES'),
                'PATH': os.environ.get('PATH', '')[:500],  # Truncate long PATH
                'PYTHONPATH': os.environ.get('PYTHONPATH'),
                'HOME': os.environ.get('HOME'),
                'USER': os.environ.get('USER')
            }
        }
        
        # Add hardware info if available
        try:
            import psutil
            env_info['hardware'] = {
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'memory_available_gb': round(psutil.virtual_memory().available / (1024**3), 2),
                'disk_usage_gb': round(psutil.disk_usage('/').total / (1024**3), 2)
            }
        except ImportError:
            env_info['hardware'] = {'error': 'psutil not available'}
        
        # Add GPU info if available
        try:
            import torch
            if torch.cuda.is_available():
                env_info['gpu'] = {
                    'cuda_available': True,
                    'cuda_version': torch.version.cuda,
                    'device_count': torch.cuda.device_count(),
                    'devices': []
                }
                for i in range(torch.cuda.device_count()):
                    device_info = {
                        'id': i,
                        'name': torch.cuda.get_device_name(i),
                        'memory_total_gb': round(torch.cuda.get_device_properties(i).total_memory / (1024**3), 2)
                    }
                    env_info['gpu']['devices'].append(device_info)
            else:
                env_info['gpu'] = {'cuda_available': False, 'reason': 'CUDA not available'}
        except ImportError:
            env_info['gpu'] = {'error': 'PyTorch not available'}
        
        # Add package versions for key dependencies
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                import pkg_resources
            key_packages = ['torch', 'transformers', 'numpy', 'pandas', 'pyyaml', 'rich']
            env_info['packages'] = {}
            for package in key_packages:
                try:
                    version = pkg_resources.get_distribution(package).version
                    env_info['packages'][package] = version
                except pkg_resources.DistributionNotFound:
                    env_info['packages'][package] = 'not installed'
        except ImportError:
            env_info['packages'] = {'error': 'pkg_resources not available'}
        
        return env_info
    
    def load_experiment_metadata(self, metadata_path: str) -> Dict[str, Any]:
        """
        Load experiment metadata from a saved metadata file.
        
        Args:
            metadata_path: Path to experiment_metadata.json file
            
        Returns:
            Loaded metadata dictionary
            
        Raises:
            FileNotFoundError: If metadata file doesn't exist
            json.JSONDecodeError: If metadata file has invalid JSON
        """
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
        
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            return metadata
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in metadata file {metadata_path}: {e}")
    
    def get_experiment_summary(self, metadata_path: str) -> Dict[str, Any]:
        """
        Get a summary of an experiment from its metadata file.
        
        Args:
            metadata_path: Path to experiment_metadata.json file
            
        Returns:
            Summary dictionary with key experiment information
        """
        metadata = self.load_experiment_metadata(metadata_path)
        
        summary = {
            'experiment_name': metadata.get('experiment_name'),
            'description': metadata.get('run_description'),
            'phase': metadata.get('config_used', {}).get('phase'),
            'start_time': metadata.get('start_time'),
            'end_time': metadata.get('end_time'),
            'duration': metadata.get('total_duration'),
            'system_platform': metadata.get('system_info', {}).get('platform'),
            'gpu_info': metadata.get('system_info', {}).get('gpu_info'),
            'models_used': metadata.get('config_used', {}).get('coders_to_run'),
            'strategies_used': metadata.get('config_used', {}).get('strategies_to_run'),
            'results_summary': metadata.get('results_summary')
        }
        
        return summary
    
    def find_experiments_by_criteria(self, results_dir: str, **criteria) -> List[Dict[str, Any]]:
        """
        Find experiments in a results directory that match given criteria.
        
        Args:
            results_dir: Directory to search for experiment metadata files
            **criteria: Key-value pairs to match against experiment metadata
                       (e.g., phase=2, experiment_name="test_run")
        
        Returns:
            List of experiment summaries that match the criteria
        """
        matching_experiments = []
        
        if not os.path.exists(results_dir):
            return matching_experiments
        
        # Look for metadata files in subdirectories
        for root, dirs, files in os.walk(results_dir):
            if 'experiment_metadata.json' in files:
                metadata_path = os.path.join(root, 'experiment_metadata.json')
                try:
                    summary = self.get_experiment_summary(metadata_path)
                    
                    # Check if this experiment matches all criteria
                    matches = True
                    for key, value in criteria.items():
                        if summary.get(key) != value:
                            matches = False
                            break
                    
                    if matches:
                        summary['metadata_path'] = metadata_path
                        summary['results_dir'] = root
                        matching_experiments.append(summary)
                        
                except Exception as e:
                    self.logger.warning(f"Could not load metadata from {metadata_path}: {e}")
        
        return matching_experiments
    
    def update_experiment_metadata(self, metadata_path: str, updates: Dict[str, Any]) -> None:
        """
        Update experiment metadata with additional information (e.g., final results).
        
        Args:
            metadata_path: Path to experiment_metadata.json file
            updates: Dictionary of updates to apply to the metadata
        """
        metadata = self.load_experiment_metadata(metadata_path)
        
        # Apply updates
        for key, value in updates.items():
            if key == 'results_summary' and isinstance(value, dict) and isinstance(metadata.get(key), dict):
                # Merge results summary instead of replacing
                metadata[key].update(value)
            else:
                metadata[key] = value
        
        # Save updated metadata
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Updated experiment metadata: {metadata_path}")
    
    def convert_args_to_config(self, args: argparse.Namespace) -> Dict[str, Any]:
        """
        Convert command-line arguments to configuration dictionary format.
        
        Used for backward compatibility when no config file is provided.
        """
        config = {
            'experiment_name': f"cli_experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'run_description': 'Experiment run from command-line arguments',
            'phase': args.phase
        }
        
        # Map arguments to config format
        if hasattr(args, 'model') and args.model:
            config['reasoning_model'] = args.model
        if hasattr(args, 'coder') and args.coder:
            config['coders_to_run'] = args.coder
        if hasattr(args, 'strategy') and args.strategy:
            config['strategies_to_run'] = args.strategy
        if hasattr(args, 'stage') and args.stage:
            config['stage'] = args.stage
        if hasattr(args, 'save_excel') and args.save_excel:
            config['save_excel'] = args.save_excel
        if hasattr(args, 'excel_per_model') and args.excel_per_model:
            config['excel_per_model'] = args.excel_per_model
        if hasattr(args, 'expected_dir') and args.expected_dir:
            config['expected_dir'] = args.expected_dir
        if hasattr(args, 'input_pickle') and args.input_pickle:
            config['input_pickle'] = args.input_pickle
        if hasattr(args, 'num_gpus') and args.num_gpus:
            config['num_gpus'] = args.num_gpus
        if hasattr(args, 'path') and args.path:
            config['input_dataset_dir'] = args.path
        
        return config