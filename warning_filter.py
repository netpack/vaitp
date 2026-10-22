#!/usr/bin/env python3
"""
Warning Filter for VAITP Framework

This module provides comprehensive warning suppression for cleaner log output.
It filters out common, useless warnings from various dependencies.
"""

import logging
import warnings
import os
import sys

class VaitpWarningFilter(logging.Filter):
    """Custom logging filter to suppress useless warnings."""
    
    def __init__(self):
        super().__init__()
        self.suppressed_patterns = [
            # Semgrep/OpenTelemetry warnings
            'pkg_resources is deprecated',
            'UserWarning: pkg_resources',
            'opentelemetry/instrumentation/dependencies.py',
            'Setuptools<81',
            'pkg_resources package is slated for removal',
            
            # Tokenizer warnings
            'The current process just got forked',
            'TOKENIZERS_PARALLELISM',
            'huggingface/tokenizers',
            
            # PyTorch warnings
            'torch.distributed.launch',
            'UserWarning: torch.meshgrid',
            
            # Other common warnings
            'FutureWarning',
            'DeprecationWarning',
            'PendingDeprecationWarning',
            
            # Specific library warnings
            'sentence_transformers',
            'transformers/tokenization_utils_base.py',
        ]
    
    def filter(self, record):
        """Filter out records that match suppressed patterns."""
        message = record.getMessage()
        
        # Check if this message should be suppressed
        for pattern in self.suppressed_patterns:
            if pattern.lower() in message.lower():
                return False  # Suppress this log record
        
        return True  # Allow this log record

def setup_warning_suppression():
    """Set up comprehensive warning suppression."""
    
    # Suppress Python warnings
    warnings.filterwarnings('ignore')
    
    # Set environment variables
    os.environ['PYTHONWARNINGS'] = 'ignore'
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    
    # Add custom filter to root logger
    root_logger = logging.getLogger()
    warning_filter = VaitpWarningFilter()
    root_logger.addFilter(warning_filter)
    
    # Also add to specific loggers that tend to be noisy
    noisy_loggers = [
        'transformers',
        'sentence_transformers',
        'torch',
        'opentelemetry',
        'urllib3',
        'requests'
    ]
    
    for logger_name in noisy_loggers:
        logger = logging.getLogger(logger_name)
        logger.addFilter(warning_filter)
        logger.setLevel(logging.ERROR)  # Only show errors from these loggers

def clean_stderr_output(stderr_text: str) -> str:
    """Clean stderr output by removing common useless warnings."""
    if not stderr_text:
        return stderr_text
    
    lines = stderr_text.split('\n')
    cleaned_lines = []
    
    suppressed_patterns = [
        'pkg_resources is deprecated',
        'UserWarning: pkg_resources',
        'opentelemetry/instrumentation/dependencies.py',
        'Setuptools<81',
        'pkg_resources package is slated for removal',
        'The current process just got forked',
        'TOKENIZERS_PARALLELISM',
    ]
    
    for line in lines:
        # Skip lines that contain suppressed patterns
        should_suppress = any(pattern in line for pattern in suppressed_patterns)
        
        if not should_suppress and line.strip():
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines).strip()

# Apply warning suppression when module is imported
setup_warning_suppression()