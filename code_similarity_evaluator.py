# code_similarity_evaluator.py

import re
import ast
import logging
from typing import Optional, Union, List, Dict, Any
from dataclasses import dataclass
import sacrebleu

# Import configuration management
try:
    from metrics_config import get_metrics_config, MetricsConfiguration
    METRICS_CONFIG_AVAILABLE = True
except ImportError:
    METRICS_CONFIG_AVAILABLE = False
    MetricsConfiguration = None

# Import new dependencies with fallback handling
try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    tree_sitter = None
    Language = None
    Parser = None
    TREE_SITTER_AVAILABLE = False

try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    rouge_scorer = None
    ROUGE_AVAILABLE = False

try:
    import editdistance
    EDITDISTANCE_AVAILABLE = True
except ImportError:
    editdistance = None
    EDITDISTANCE_AVAILABLE = False


@dataclass
class CodeMetrics:
    """
    Official return type for evaluate_all_metrics method.
    Provides type safety and self-documenting code structure.
    """
    code_bleu_score: float
    bleu_4_score: float  # Replaces legacy bleu_score
    rouge_l_score: float
    normalized_edit_distance: float
    calculation_errors: List[str]
    preprocessing_successful: bool
    
    # Legacy compatibility (will be removed in future version)
    @property
    def bleu_score(self) -> float:
        """Deprecated: Use bleu_4_score instead."""
        return self.bleu_4_score


class CodeSimilarityEvaluator:
    """
    A comprehensive utility class for evaluating code similarity using multiple quantitative metrics.
    
    This class provides methods to calculate similarity scores between generated code and expected code
    using four different metrics:
    
    1. **BLEU-4**: Standard BLEU score with 4-gram precision, widely used for text similarity
    2. **ROUGE-L**: Longest Common Subsequence-based recall metric, good for structural similarity
    3. **CodeBLEU**: AST-aware metric that considers syntactic structure and data flow
    4. **Normalized Edit Distance**: Character-level similarity with aggressive normalization
    
    Features:
    - **Configurable Metrics**: Enable/disable individual metrics based on requirements
    - **Performance Tuning**: Configurable timeouts, memory limits, and code size constraints
    - **Graceful Degradation**: Continues evaluation even if some metrics fail
    - **Dependency Management**: Automatically handles missing optional dependencies
    - **Composite Scoring**: Weighted combination of multiple metrics for overall similarity
    - **Comprehensive Error Handling**: Detailed error reporting and fallback mechanisms
    
    Usage Examples:
    
    Basic usage with default configuration:
    ```python
    evaluator = CodeSimilarityEvaluator()
    metrics = evaluator.evaluate_all_metrics(generated_code, expected_code)
    print(f"BLEU-4: {metrics.bleu_4_score:.3f}")
    print(f"Composite Score: {evaluator.calculate_composite_score(metrics):.3f}")
    ```
    
    Custom configuration:
    ```python
    from metrics_config import MetricsConfiguration
    
    config = MetricsConfiguration(
        enable_code_bleu=True,
        enable_bleu_4=True,
        enable_rouge_l=False,  # Disable for faster evaluation
        enable_edit_distance=True,
        max_code_size_bytes=500_000,
        ast_parsing_timeout_seconds=20
    )
    
    evaluator = CodeSimilarityEvaluator(config=config)
    metrics = evaluator.evaluate_all_metrics(generated_code, expected_code)
    ```
    
    Environment-aware configuration (recommended for production):
    ```python
    from metrics_config import get_recommended_metrics_config
    
    config = get_recommended_metrics_config()  # Auto-handles missing dependencies
    evaluator = CodeSimilarityEvaluator(config=config)
    ```
    
    Attributes:
        config: MetricsConfiguration instance controlling evaluation behavior
        logger: Logger instance for debugging and error reporting
    
    Note:
        The legacy `calculate_bleu_score()` method is deprecated but still available
        for backward compatibility. Use `evaluate_all_metrics()` for new code.
    """
    
    def __init__(self, config: Optional[MetricsConfiguration] = None):
        """
        Initialize the CodeSimilarityEvaluator with optional configuration.
        
        Args:
            config: Optional MetricsConfiguration instance. If None, uses default configuration.
        """
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        if config is not None:
            self.config = config
        elif METRICS_CONFIG_AVAILABLE:
            self.config = get_metrics_config()
        else:
            # Fallback configuration if metrics_config is not available
            self.config = self._create_fallback_config()
            self.logger.warning("Using fallback configuration - metrics_config module not available")
        
        # Log configuration
        self.logger.info(f"Initialized CodeSimilarityEvaluator with config: {self.config.get_enabled_metrics()}")
    
    def _create_fallback_config(self) -> Any:
        """
        Create a fallback configuration object when metrics_config is not available.
        
        Returns:
            Simple configuration object with basic attributes
        """
        class FallbackConfig:
            def __init__(self):
                self.enable_code_bleu = True
                self.enable_bleu_4 = True
                self.enable_rouge_l = True
                self.enable_edit_distance = True
                self.max_code_size_bytes = 1_000_000
                self.max_tokens_per_file = 10_000
                self.ast_parsing_timeout_seconds = 30
                self.memory_limit_mb = 100
                self.fail_gracefully = True
                self.default_failed_metric_value = -1.0
                self.log_missing_dependencies = True
            
            def get_enabled_metrics(self):
                return ["code_bleu", "bleu_4", "rouge_l", "edit_distance"]
            
            def calculate_composite_score(self, metrics):
                # Simple average of valid scores
                valid_scores = [v for v in metrics.values() if isinstance(v, (int, float)) and v >= 0]
                return sum(valid_scores) / len(valid_scores) if valid_scores else 0.0
        
        return FallbackConfig()
    
    def preprocess_code(self, code: Union[str, None]) -> str:
        """
        Normalize code for fair comparison by removing comments, normalizing whitespace,
        and handling common formatting differences.
        
        Args:
            code (Union[str, None]): The code string to preprocess
            
        Returns:
            str: The preprocessed code string
            
        Raises:
            None: All exceptions are caught and handled gracefully
        """
        # Handle None and non-string inputs
        if code is None:
            return ""
        
        if not isinstance(code, str):
            self.logger.warning(f"preprocess_code received non-string input of type {type(code)}")
            try:
                code = str(code)
            except Exception as e:
                self.logger.error(f"Failed to convert input to string: {e}")
                return ""
        
        # Handle empty string
        if not code.strip():
            return ""
        
        try:
            # Remove leading/trailing whitespace
            code = code.strip()
            
            # Validate code length to prevent memory issues using configuration
            max_size = getattr(self.config, 'max_code_size_bytes', 1_000_000)
            if len(code) > max_size:
                self.logger.warning(f"Code too large ({len(code)} chars), truncating to {max_size} bytes")
                code = code[:max_size]
            
            # Remove single-line comments (# comments)
            code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
            
            # Remove multi-line comments and docstrings
            # This is a simplified approach - for more robust handling,
            # we could use AST parsing
            code = re.sub(r'""".*?"""', "", code, flags=re.DOTALL)
            code = re.sub(r"'''.*?'''", "", code, flags=re.DOTALL)
            
            # Normalize whitespace - replace multiple spaces/tabs with single space
            code = re.sub(r"[ \t]+", " ", code)
            
            # Remove empty lines and normalize line endings
            lines = [line.strip() for line in code.splitlines() if line.strip()]
            code = "\n".join(lines)
            
            # Additional normalization: remove trailing semicolons if present
            # (some code might have them, others might not)
            code = re.sub(r";\s*$", "", code, flags=re.MULTILINE)
            
            return code.strip()
            
        except re.error as e:
            self.logger.error(f"Regex error in code preprocessing: {e}")
            # Return minimally processed code
            return code.strip() if isinstance(code, str) else ""
        except MemoryError as e:
            self.logger.error(f"Memory error in code preprocessing: {e}")
            # Try with truncated code
            try:
                truncated_code = code[:10000] if isinstance(code, str) else ""
                return truncated_code.strip()
            except Exception:
                return ""
        except Exception as e:
            self.logger.warning(f"Unexpected error preprocessing code: {e}")
            # Return original code if preprocessing fails
            return code.strip() if isinstance(code, str) else ""
    
    def calculate_bleu_score(self, generated_code: Union[str, None], expected_code: Union[str, None]) -> float:
        """
        Calculate BLEU similarity score between generated and expected code.
        
        DEPRECATED: This method is deprecated. Use evaluate_all_metrics() instead
        for comprehensive code similarity evaluation including BLEU-4, ROUGE-L,
        CodeBLEU, and Normalized Edit Distance.
        
        Args:
            generated_code (Union[str, None]): The generated code to evaluate
            expected_code (Union[str, None]): The expected/reference code
            
        Returns:
            float: BLEU score between 0.0 and 1.0 (higher is better)
            
        Raises:
            None: All exceptions are caught and handled gracefully, returning 0.0 on error
        """
        import warnings
        warnings.warn(
            "calculate_bleu_score() is deprecated. Use evaluate_all_metrics() instead "
            "for comprehensive code similarity evaluation.",
            DeprecationWarning,
            stacklevel=2
        )
        try:
            # Validate inputs
            if generated_code is None:
                generated_code = ""
            if expected_code is None:
                expected_code = ""
                
            if not isinstance(generated_code, str):
                self.logger.warning(f"Generated code is not a string: {type(generated_code)}")
                try:
                    generated_code = str(generated_code)
                except Exception as e:
                    self.logger.error(f"Failed to convert generated code to string: {e}")
                    return 0.0
                    
            if not isinstance(expected_code, str):
                self.logger.warning(f"Expected code is not a string: {type(expected_code)}")
                try:
                    expected_code = str(expected_code)
                except Exception as e:
                    self.logger.error(f"Failed to convert expected code to string: {e}")
                    return 0.0
            
            # Handle edge cases
            if not generated_code and not expected_code:
                return 1.0  # Both empty - perfect match
            
            if not generated_code or not expected_code:
                return 0.0  # One empty, one not - no similarity
            
            # Preprocess both code strings with error handling
            try:
                processed_generated = self.preprocess_code(generated_code)
                processed_expected = self.preprocess_code(expected_code)
            except Exception as e:
                self.logger.error(f"Error during code preprocessing: {e}")
                # Fallback to minimal processing
                processed_generated = generated_code.strip() if generated_code else ""
                processed_expected = expected_code.strip() if expected_code else ""
            
            # Handle edge cases after preprocessing
            if not processed_generated and not processed_expected:
                return 1.0  # Both empty after preprocessing - perfect match
            
            if not processed_generated or not processed_expected:
                return 0.0  # One empty after preprocessing - no similarity
            
            # Check for identical code
            if processed_generated == processed_expected:
                return 1.0  # Perfect match
            
            # Split code into tokens for BLEU calculation with error handling
            try:
                generated_tokens = self._tokenize_code(processed_generated)
                expected_tokens = self._tokenize_code(processed_expected)
            except Exception as e:
                self.logger.error(f"Error during code tokenization: {e}")
                # Fallback to simple whitespace tokenization
                generated_tokens = processed_generated.split()
                expected_tokens = processed_expected.split()
            
            if not generated_tokens or not expected_tokens:
                self.logger.debug("Empty token lists after tokenization")
                return 0.0
            
            # Validate token counts to prevent sacrebleu issues
            if len(generated_tokens) > 10000 or len(expected_tokens) > 10000:
                self.logger.warning(f"Large token count: gen={len(generated_tokens)}, exp={len(expected_tokens)}")
                # Truncate tokens to prevent memory/performance issues
                generated_tokens = generated_tokens[:10000]
                expected_tokens = expected_tokens[:10000]
            
            # Convert token lists to strings for sacrebleu
            try:
                generated_text = " ".join(generated_tokens)
                expected_text = " ".join(expected_tokens)
            except Exception as e:
                self.logger.error(f"Error joining tokens: {e}")
                return 0.0
            
            # Calculate BLEU score using sacrebleu with comprehensive error handling
            try:
                bleu = sacrebleu.sentence_bleu(
                    hypothesis=generated_text,
                    references=[expected_text],
                    smooth_method='exp',  # Use exponential smoothing for better handling of short sequences
                    smooth_value=0.1
                )
                
                # Validate BLEU result
                if not hasattr(bleu, 'score'):
                    self.logger.error("BLEU result missing score attribute")
                    return 0.0
                
                raw_score = bleu.score
                
                # Validate score is numeric
                if not isinstance(raw_score, (int, float)):
                    self.logger.error(f"BLEU score is not numeric: {type(raw_score)}")
                    return 0.0
                
                # Handle NaN or infinite values
                if not (raw_score == raw_score):  # NaN check
                    self.logger.warning("BLEU score is NaN")
                    return 0.0
                
                if raw_score == float('inf') or raw_score == float('-inf'):
                    self.logger.warning(f"BLEU score is infinite: {raw_score}")
                    return 0.0
                
                # Convert to 0-1 scale (BLEU score is typically 0-100)
                score = raw_score / 100.0
                
                # Ensure score is within bounds
                score = max(0.0, min(1.0, score))
                
                return score
                
            except ImportError as e:
                self.logger.error(f"sacrebleu import error: {e}")
                return 0.0
            except AttributeError as e:
                self.logger.error(f"sacrebleu attribute error: {e}")
                return 0.0
            except ValueError as e:
                self.logger.error(f"sacrebleu value error: {e}")
                return 0.0
            except MemoryError as e:
                self.logger.error(f"Memory error in BLEU calculation: {e}")
                return 0.0
            except Exception as e:
                self.logger.error(f"Unexpected error in sacrebleu calculation: {e}")
                return 0.0
            
        except Exception as e:
            self.logger.error(f"Critical error in calculate_bleu_score: {e}")
            return 0.0
    
    def _tokenize_code(self, code: Union[str, None]) -> list[str]:
        """
        Tokenize code into a list of tokens for BLEU calculation.
        
        Args:
            code (Union[str, None]): The code to tokenize
            
        Returns:
            list[str]: List of tokens
            
        Raises:
            None: All exceptions are caught and handled gracefully
        """
        if not code or code is None:
            return []
        
        if not isinstance(code, str):
            self.logger.warning(f"_tokenize_code received non-string input: {type(code)}")
            try:
                code = str(code)
            except Exception as e:
                self.logger.error(f"Failed to convert code to string for tokenization: {e}")
                return []
        
        try:
            # Validate code length to prevent performance issues
            if len(code) > 100_000:  # 100KB limit for tokenization
                self.logger.warning(f"Code too large for tokenization ({len(code)} chars), truncating")
                code = code[:100_000]
            
            # Split by whitespace and common code delimiters
            # This creates a token-based representation suitable for BLEU
            tokens = []
            
            # Split by lines first, then by common delimiters
            try:
                lines = code.splitlines()
            except Exception as e:
                self.logger.error(f"Error splitting code into lines: {e}")
                # Fallback to treating entire code as one line
                lines = [code]
            
            for line in lines:
                if not line or not line.strip():
                    continue
                
                try:
                    # Split by common Python delimiters while preserving multi-character operators
                    # Match multi-character operators first, then single characters
                    line_tokens = re.findall(r'>=|<=|==|!=|\*\*|//|<<|>>|\w+|[^\w\s]', line)
                    tokens.extend(line_tokens)
                except re.error as e:
                    self.logger.error(f"Regex error in tokenization: {e}")
                    # Fallback to simple split
                    line_tokens = line.split()
                    tokens.extend(line_tokens)
                except Exception as e:
                    self.logger.warning(f"Error tokenizing line '{line[:50]}...': {e}")
                    # Skip problematic line
                    continue
            
            # Filter and validate tokens
            try:
                filtered_tokens = []
                for token in tokens:
                    if token and isinstance(token, str) and token.strip():
                        # Limit individual token length to prevent issues
                        if len(token) > 1000:
                            token = token[:1000]
                        filtered_tokens.append(token.strip())
                
                return filtered_tokens
            except Exception as e:
                self.logger.error(f"Error filtering tokens: {e}")
                # Return raw tokens if filtering fails
                return [str(t) for t in tokens if t]
            
        except MemoryError as e:
            self.logger.error(f"Memory error in tokenization: {e}")
            # Fallback: simple whitespace split with truncation
            try:
                truncated_code = code[:1000] if len(code) > 1000 else code
                return truncated_code.split()
            except Exception:
                return []
        except Exception as e:
            self.logger.warning(f"Unexpected error tokenizing code: {e}")
            # Fallback: simple whitespace split
            try:
                return code.split()
            except Exception as fallback_error:
                self.logger.error(f"Fallback tokenization also failed: {fallback_error}")
                return []
    
    def validate_syntax(self, code: Union[str, None]) -> bool:
        """
        Validate that the code has valid Python syntax.
        
        Args:
            code (Union[str, None]): The code to validate
            
        Returns:
            bool: True if syntax is valid, False otherwise
            
        Raises:
            None: All exceptions are caught and handled gracefully
        """
        if code is None:
            return False
            
        if not isinstance(code, str):
            self.logger.warning(f"validate_syntax received non-string input: {type(code)}")
            try:
                code = str(code)
            except Exception as e:
                self.logger.error(f"Failed to convert code to string for syntax validation: {e}")
                return False
        
        if not code.strip():
            return False
        
        try:
            # Validate code length to prevent parser issues
            if len(code) > 1_000_000:  # 1MB limit
                self.logger.warning(f"Code too large for syntax validation ({len(code)} chars)")
                return False
            
            ast.parse(code)
            return True
        except SyntaxError as e:
            self.logger.debug(f"Syntax error in code validation: {e}")
            return False
        except ValueError as e:
            self.logger.warning(f"Value error in syntax validation: {e}")
            return False
        except MemoryError as e:
            self.logger.error(f"Memory error in syntax validation: {e}")
            return False
        except RecursionError as e:
            self.logger.error(f"Recursion error in syntax validation (code too complex): {e}")
            return False
        except Exception as e:
            self.logger.warning(f"Unexpected error validating syntax: {e}")
            return False
    
    def evaluate_with_metadata(self, generated_code: Union[str, None], expected_code: Union[str, None]) -> dict:
        """
        Evaluate code similarity and return detailed metadata.
        
        Args:
            generated_code (Union[str, None]): The generated code to evaluate
            expected_code (Union[str, None]): The expected/reference code
            
        Returns:
            dict: Dictionary containing BLEU score and additional metadata
            
        Raises:
            None: All exceptions are caught and handled gracefully
        """
        # Initialize result with safe defaults
        result = {
            'bleu_score': 0.0,
            'generated_valid_syntax': False,
            'expected_valid_syntax': False,
            'generated_length': 0,
            'expected_length': 0,
            'preprocessing_successful': True,
            'error_details': None
        }
        
        try:
            # Handle None inputs
            if generated_code is None:
                generated_code = ""
            if expected_code is None:
                expected_code = ""
            
            # Convert to strings if needed
            if not isinstance(generated_code, str):
                try:
                    generated_code = str(generated_code)
                except Exception as e:
                    self.logger.error(f"Failed to convert generated_code to string: {e}")
                    result['error_details'] = f"Generated code conversion error: {e}"
                    result['preprocessing_successful'] = False
                    return result
            
            if not isinstance(expected_code, str):
                try:
                    expected_code = str(expected_code)
                except Exception as e:
                    self.logger.error(f"Failed to convert expected_code to string: {e}")
                    result['error_details'] = f"Expected code conversion error: {e}"
                    result['preprocessing_successful'] = False
                    return result
            
            # Calculate lengths safely
            try:
                result['generated_length'] = len(generated_code)
                result['expected_length'] = len(expected_code)
            except Exception as e:
                self.logger.warning(f"Error calculating code lengths: {e}")
                result['generated_length'] = 0
                result['expected_length'] = 0
            
            # Validate syntax with error handling
            try:
                result['generated_valid_syntax'] = self.validate_syntax(generated_code)
            except Exception as e:
                self.logger.error(f"Error validating generated code syntax: {e}")
                result['generated_valid_syntax'] = False
                result['preprocessing_successful'] = False
            
            try:
                result['expected_valid_syntax'] = self.validate_syntax(expected_code)
            except Exception as e:
                self.logger.error(f"Error validating expected code syntax: {e}")
                result['expected_valid_syntax'] = False
                result['preprocessing_successful'] = False
            
            # Calculate BLEU score with error handling
            try:
                result['bleu_score'] = self.calculate_bleu_score(generated_code, expected_code)
            except Exception as e:
                self.logger.error(f"Error calculating BLEU score in metadata evaluation: {e}")
                result['bleu_score'] = 0.0
                result['preprocessing_successful'] = False
                if result['error_details'] is None:
                    result['error_details'] = f"BLEU calculation error: {e}"
            
        except Exception as e:
            self.logger.error(f"Critical error in evaluate_with_metadata: {e}")
            result['preprocessing_successful'] = False
            result['error_details'] = f"Critical evaluation error: {e}"
        
        return result
    
    def is_sacrebleu_available(self) -> bool:
        """
        Check if sacrebleu is properly installed and available.
        
        Returns:
            bool: True if sacrebleu is available, False otherwise
        """
        try:
            import sacrebleu
            # Test basic functionality
            test_result = sacrebleu.sentence_bleu("test", ["test"])
            return hasattr(test_result, 'score')
        except ImportError:
            self.logger.error("sacrebleu is not installed")
            return False
        except Exception as e:
            self.logger.error(f"sacrebleu is not functioning properly: {e}")
            return False
    
    def calculate_fallback_similarity(self, generated_code: str, expected_code: str) -> float:
        """
        Calculate a simple fallback similarity score when BLEU calculation fails.
        
        Args:
            generated_code (str): The generated code
            expected_code (str): The expected code
            
        Returns:
            float: Simple similarity score between 0.0 and 1.0
        """
        try:
            if not generated_code and not expected_code:
                return 1.0
            
            if not generated_code or not expected_code:
                return 0.0
            
            # Simple character-based similarity
            gen_chars = set(generated_code.lower())
            exp_chars = set(expected_code.lower())
            
            if not gen_chars and not exp_chars:
                return 1.0
            
            if not gen_chars or not exp_chars:
                return 0.0
            
            intersection = len(gen_chars.intersection(exp_chars))
            union = len(gen_chars.union(exp_chars))
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Error in fallback similarity calculation: {e}")
            return 0.0
    
    def _calculate_bleu_4_score(self, generated_code: str, expected_code: str) -> float:
        """
        Calculate BLEU-4 score using sacrebleu with explicit BLEU-4 configuration.
        
        Args:
            generated_code (str): The generated code to evaluate
            expected_code (str): The expected/reference code
            
        Returns:
            float: BLEU-4 score between 0.0 and 1.0 (higher is better)
            
        Raises:
            Exception: Re-raises exceptions for caller to handle
        """
        # Input validation
        if not isinstance(generated_code, str) or not isinstance(expected_code, str):
            raise ValueError("Both generated_code and expected_code must be strings")
        
        # Handle edge cases
        if not generated_code.strip() and not expected_code.strip():
            return 1.0  # Both empty - perfect match
        
        if not generated_code.strip() or not expected_code.strip():
            return 0.0  # One empty, one not - no similarity
        
        # Preprocess both code strings
        processed_generated = self.preprocess_code(generated_code)
        processed_expected = self.preprocess_code(expected_code)
        
        # Handle edge cases after preprocessing
        if not processed_generated and not processed_expected:
            return 1.0  # Both empty after preprocessing - perfect match
        
        if not processed_generated or not processed_expected:
            return 0.0  # One empty after preprocessing - no similarity
        
        # Check for identical code
        if processed_generated == processed_expected:
            return 1.0  # Perfect match
        
        # Tokenize code
        generated_tokens = self._tokenize_code(processed_generated)
        expected_tokens = self._tokenize_code(processed_expected)
        
        if not generated_tokens or not expected_tokens:
            return 0.0
        
        # Validate token counts to prevent sacrebleu issues
        if len(generated_tokens) > 10000 or len(expected_tokens) > 10000:
            self.logger.warning(f"Large token count: gen={len(generated_tokens)}, exp={len(expected_tokens)}")
            generated_tokens = generated_tokens[:10000]
            expected_tokens = expected_tokens[:10000]
        
        # Convert token lists to strings for sacrebleu
        generated_text = " ".join(generated_tokens)
        expected_text = " ".join(expected_tokens)
        
        # Calculate BLEU-4 score using sacrebleu with explicit configuration
        bleu = sacrebleu.sentence_bleu(
            hypothesis=generated_text,
            references=[expected_text],
            smooth_method='exp',  # Use exponential smoothing for better handling of short sequences
            smooth_value=0.1
        )
        
        # Validate BLEU result
        if not hasattr(bleu, 'score'):
            raise RuntimeError("BLEU result missing score attribute")
        
        raw_score = bleu.score
        
        # Validate score is numeric
        if not isinstance(raw_score, (int, float)):
            raise TypeError(f"BLEU score is not numeric: {type(raw_score)}")
        
        # Handle NaN or infinite values
        if not (raw_score == raw_score):  # NaN check
            raise ValueError("BLEU score is NaN")
        
        if raw_score == float('inf') or raw_score == float('-inf'):
            raise ValueError(f"BLEU score is infinite: {raw_score}")
        
        # Convert to 0-1 scale (BLEU score is typically 0-100)
        score = raw_score / 100.0
        
        # Ensure score is within bounds
        score = max(0.0, min(1.0, score))
        
        return score

    def _calculate_rouge_l_score(self, generated_code: str, expected_code: str) -> float:
        """
        Calculate ROUGE-L score using rouge-score library.
        ROUGE-L measures the longest common subsequence recall.
        
        Args:
            generated_code (str): The generated code to evaluate
            expected_code (str): The expected/reference code
            
        Returns:
            float: ROUGE-L score between 0.0 and 1.0 (higher is better)
            
        Raises:
            Exception: Re-raises exceptions for caller to handle
        """
        # Check if rouge-score library is available
        if not ROUGE_AVAILABLE:
            raise ImportError("rouge-score library is not available")
        
        # Input validation
        if not isinstance(generated_code, str) or not isinstance(expected_code, str):
            raise ValueError("Both generated_code and expected_code must be strings")
        
        # Handle edge cases
        if not generated_code.strip() and not expected_code.strip():
            return 1.0  # Both empty - perfect match
        
        if not generated_code.strip() or not expected_code.strip():
            return 0.0  # One empty, one not - no similarity
        
        # Preprocess both code strings for ROUGE calculation
        processed_generated = self._preprocess_code_for_rouge(generated_code)
        processed_expected = self._preprocess_code_for_rouge(expected_code)
        
        # Handle edge cases after preprocessing
        if not processed_generated and not processed_expected:
            return 1.0  # Both empty after preprocessing - perfect match
        
        if not processed_generated or not processed_expected:
            return 0.0  # One empty after preprocessing - no similarity
        
        # Check for identical code
        if processed_generated == processed_expected:
            return 1.0  # Perfect match
        
        # Initialize ROUGE scorer for ROUGE-L
        scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=False)
        
        # Calculate ROUGE-L score
        scores = scorer.score(processed_expected, processed_generated)
        rouge_l_score = scores['rougeL'].fmeasure
        
        # Validate score
        if not isinstance(rouge_l_score, (int, float)):
            raise TypeError(f"ROUGE-L score is not numeric: {type(rouge_l_score)}")
        
        # Handle NaN or infinite values
        if not (rouge_l_score == rouge_l_score):  # NaN check
            raise ValueError("ROUGE-L score is NaN")
        
        if rouge_l_score == float('inf') or rouge_l_score == float('-inf'):
            raise ValueError(f"ROUGE-L score is infinite: {rouge_l_score}")
        
        # Ensure score is within bounds
        score = max(0.0, min(1.0, rouge_l_score))
        
        return score

    def _preprocess_code_for_rouge(self, code: str) -> str:
        """
        Preprocess code specifically for ROUGE calculation.
        ROUGE works better with text-like preprocessing.
        
        Args:
            code (str): The code to preprocess
            
        Returns:
            str: Preprocessed code suitable for ROUGE calculation
        """
        if not code or not isinstance(code, str):
            return ""
        
        try:
            # Start with basic preprocessing
            processed = self.preprocess_code(code)
            
            if not processed:
                return ""
            
            # Additional preprocessing for ROUGE:
            # ROUGE works on sequences, so we want to preserve more structure
            # but still normalize for fair comparison
            
            # Split into tokens and rejoin with single spaces
            # This helps ROUGE find longer common subsequences
            tokens = self._tokenize_code(processed)
            if not tokens:
                return ""
            
            # Join tokens with single spaces for ROUGE processing
            rouge_text = " ".join(tokens)
            
            return rouge_text.strip()
            
        except Exception as e:
            self.logger.error(f"Error in ROUGE preprocessing: {e}")
            # Fallback to basic preprocessing
            return self.preprocess_code(code)

    def _calculate_normalized_edit_distance(self, generated_code: str, expected_code: str) -> float:
        """
        Calculate normalized edit distance using editdistance library.
        Returns similarity score (1 - normalized_distance) where higher is better.
        
        Args:
            generated_code (str): The generated code to evaluate
            expected_code (str): The expected/reference code
            
        Returns:
            float: Normalized edit distance similarity score between 0.0 and 1.0 (higher is better)
            
        Raises:
            Exception: Re-raises exceptions for caller to handle
        """
        # Check if editdistance library is available
        if not EDITDISTANCE_AVAILABLE:
            raise ImportError("editdistance library is not available")
        
        # Input validation
        if not isinstance(generated_code, str) or not isinstance(expected_code, str):
            raise ValueError("Both generated_code and expected_code must be strings")
        
        # Handle edge cases
        if not generated_code.strip() and not expected_code.strip():
            return 1.0  # Both empty - perfect match
        
        if not generated_code.strip() or not expected_code.strip():
            return 0.0  # One empty, one not - no similarity
        
        # Preprocess both code strings with aggressive normalization for edit distance
        processed_generated = self._preprocess_code_for_edit_distance(generated_code)
        processed_expected = self._preprocess_code_for_edit_distance(expected_code)
        
        # Handle edge cases after preprocessing
        if not processed_generated and not processed_expected:
            return 1.0  # Both empty after preprocessing - perfect match
        
        if not processed_generated or not processed_expected:
            return 0.0  # One empty after preprocessing - no similarity
        
        # Check for identical code
        if processed_generated == processed_expected:
            return 1.0  # Perfect match
        
        # Calculate edit distance
        edit_dist = editdistance.eval(processed_generated, processed_expected)
        
        # Validate edit distance result
        if not isinstance(edit_dist, (int, float)):
            raise TypeError(f"Edit distance is not numeric: {type(edit_dist)}")
        
        if edit_dist < 0:
            raise ValueError(f"Edit distance cannot be negative: {edit_dist}")
        
        # Calculate maximum possible distance (length of longer string)
        max_length = max(len(processed_generated), len(processed_expected))
        
        if max_length == 0:
            return 1.0  # Both strings are empty
        
        # Normalize edit distance to [0, 1] range
        normalized_distance = edit_dist / max_length
        
        # Convert to similarity score (1 - distance)
        similarity_score = 1.0 - normalized_distance
        
        # Ensure score is within bounds
        similarity_score = max(0.0, min(1.0, similarity_score))
        
        return similarity_score

    def _preprocess_code_for_edit_distance(self, code: str) -> str:
        """
        Preprocess code with aggressive normalization for edit distance calculation.
        This includes variable name normalization and character-level normalization.
        
        Args:
            code (str): The code to preprocess
            
        Returns:
            str: Aggressively normalized code suitable for edit distance calculation
        """
        if not code or not isinstance(code, str):
            return ""
        
        try:
            # Start with basic preprocessing
            processed = self.preprocess_code(code)
            
            if not processed:
                return ""
            
            # Additional aggressive normalization for edit distance:
            
            # 1. Normalize variable names to generic placeholders
            processed = self._normalize_variable_names(processed)
            
            # 2. Normalize string literals
            processed = self._normalize_string_literals(processed)
            
            # 3. Normalize numeric literals
            processed = self._normalize_numeric_literals(processed)
            
            # 4. Remove all whitespace for character-level comparison
            processed = re.sub(r'\s+', '', processed)
            
            # 5. Convert to lowercase for case-insensitive comparison
            processed = processed.lower()
            
            return processed
            
        except Exception as e:
            self.logger.error(f"Error in edit distance preprocessing: {e}")
            # Fallback to basic preprocessing with whitespace removal
            try:
                basic = self.preprocess_code(code)
                return re.sub(r'\s+', '', basic.lower())
            except Exception:
                return ""

    def _normalize_variable_names(self, code: str) -> str:
        """
        Normalize variable names to generic placeholders for structural comparison.
        
        Args:
            code (str): The code to normalize
            
        Returns:
            str: Code with normalized variable names
        """
        try:
            # Simple variable name normalization using regex
            # This is a basic approach - for more sophisticated normalization,
            # we could use AST parsing
            
            # Find potential variable names (identifiers that aren't keywords)
            python_keywords = {
                'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
                'elif', 'else', 'except', 'exec', 'finally', 'for', 'from', 'global',
                'if', 'import', 'in', 'is', 'lambda', 'not', 'or', 'pass', 'print',
                'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False',
                'None', 'self', 'cls'
            }
            
            # Find all identifiers
            identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
            
            # Create mapping for non-keyword identifiers
            var_mapping = {}
            var_counter = 0
            
            for identifier in identifiers:
                if identifier not in python_keywords and identifier not in var_mapping:
                    var_mapping[identifier] = f'var{var_counter}'
                    var_counter += 1
            
            # Replace variables with normalized names
            normalized_code = code
            for original, normalized in var_mapping.items():
                # Use word boundaries to avoid partial replacements
                normalized_code = re.sub(r'\b' + re.escape(original) + r'\b', normalized, normalized_code)
            
            return normalized_code
            
        except Exception as e:
            self.logger.error(f"Error normalizing variable names: {e}")
            return code

    def _normalize_string_literals(self, code: str) -> str:
        """
        Normalize string literals to generic placeholders.
        
        Args:
            code (str): The code to normalize
            
        Returns:
            str: Code with normalized string literals
        """
        try:
            # Replace string literals with generic placeholder
            # Handle both single and double quotes
            code = re.sub(r'"[^"]*"', '"STR"', code)
            code = re.sub(r"'[^']*'", "'STR'", code)
            
            # Handle triple-quoted strings
            code = re.sub(r'""".*?"""', '"""STR"""', code, flags=re.DOTALL)
            code = re.sub(r"'''.*?'''", "'''STR'''", code, flags=re.DOTALL)
            
            return code
            
        except Exception as e:
            self.logger.error(f"Error normalizing string literals: {e}")
            return code

    def _normalize_numeric_literals(self, code: str) -> str:
        """
        Normalize numeric literals to generic placeholders.
        
        Args:
            code (str): The code to normalize
            
        Returns:
            str: Code with normalized numeric literals
        """
        try:
            # Replace integer literals
            code = re.sub(r'\b\d+\b', 'NUM', code)
            
            # Replace float literals
            code = re.sub(r'\b\d+\.\d+\b', 'NUM', code)
            
            # Replace scientific notation
            code = re.sub(r'\b\d+\.?\d*[eE][+-]?\d+\b', 'NUM', code)
            
            return code
            
        except Exception as e:
            self.logger.error(f"Error normalizing numeric literals: {e}")
            return code

    def _calculate_code_bleu_score(self, generated_code: str, expected_code: str) -> float:
        """
        Calculate CodeBLEU score with AST parsing integration.
        CodeBLEU combines lexical, AST, and data-flow similarity.
        
        Args:
            generated_code (str): The generated code to evaluate
            expected_code (str): The expected/reference code
            
        Returns:
            float: CodeBLEU score between 0.0 and 1.0 (higher is better)
            
        Raises:
            Exception: Re-raises exceptions for caller to handle
        """
        # Input validation
        if not isinstance(generated_code, str) or not isinstance(expected_code, str):
            raise ValueError("Both generated_code and expected_code must be strings")
        
        # Handle edge cases
        if not generated_code.strip() and not expected_code.strip():
            return 1.0  # Both empty - perfect match
        
        if not generated_code.strip() or not expected_code.strip():
            return 0.0  # One empty, one not - no similarity
        
        # Preprocess both code strings
        processed_generated = self.preprocess_code(generated_code)
        processed_expected = self.preprocess_code(expected_code)
        
        # Handle edge cases after preprocessing
        if not processed_generated and not processed_expected:
            return 1.0  # Both empty after preprocessing - perfect match
        
        if not processed_generated or not processed_expected:
            return 0.0  # One empty after preprocessing - no similarity
        
        # Check for identical code
        if processed_generated == processed_expected:
            return 1.0  # Perfect match
        
        # Calculate individual components of CodeBLEU
        try:
            # 1. Lexical similarity (BLEU-4)
            lexical_score = self._calculate_bleu_4_score(processed_generated, processed_expected)
            
            # 2. AST similarity
            ast_score = self._calculate_ast_similarity(processed_generated, processed_expected)
            
            # 3. Data-flow similarity (simplified - based on variable usage patterns)
            dataflow_score = self._calculate_dataflow_similarity(processed_generated, processed_expected)
            
            # Combine scores with weights (following CodeBLEU paper)
            # Weights: lexical=0.25, AST=0.25, data-flow=0.5
            code_bleu_score = (0.25 * lexical_score + 
                             0.25 * ast_score + 
                             0.5 * dataflow_score)
            
            # Ensure score is within bounds
            code_bleu_score = max(0.0, min(1.0, code_bleu_score))
            
            return code_bleu_score
            
        except Exception as e:
            self.logger.error(f"Error calculating CodeBLEU components: {e}")
            # Fallback to lexical similarity only
            return self._calculate_bleu_4_score(processed_generated, processed_expected)

    def _calculate_ast_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate AST structural similarity between two code snippets.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: AST similarity score between 0.0 and 1.0
        """
        try:
            if TREE_SITTER_AVAILABLE:
                return self._calculate_ast_similarity_tree_sitter(code1, code2)
            else:
                # Fallback to Python AST
                return self._calculate_ast_similarity_python_ast(code1, code2)
        except Exception as e:
            self.logger.error(f"Error in AST similarity calculation: {e}")
            # Fallback to simple structural similarity
            return self._calculate_simple_structural_similarity(code1, code2)

    def _calculate_ast_similarity_tree_sitter(self, code1: str, code2: str) -> float:
        """
        Calculate AST similarity using tree-sitter parser.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: AST similarity score between 0.0 and 1.0
        """
        try:
            # Initialize tree-sitter parser for Python
            parser = Parser()
            # Note: This would require tree-sitter-python to be properly installed
            # For now, we'll use a fallback approach
            
            # Extract AST features from both code snippets
            features1 = self._extract_ast_features_tree_sitter(code1)
            features2 = self._extract_ast_features_tree_sitter(code2)
            
            # Calculate similarity based on AST features
            return self._compare_ast_features(features1, features2)
            
        except Exception as e:
            self.logger.error(f"Tree-sitter AST similarity failed: {e}")
            # Fallback to Python AST
            return self._calculate_ast_similarity_python_ast(code1, code2)

    def _calculate_ast_similarity_python_ast(self, code1: str, code2: str) -> float:
        """
        Calculate AST similarity using Python's built-in AST module.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: AST similarity score between 0.0 and 1.0
        """
        try:
            # Parse both code snippets into ASTs
            ast1 = ast.parse(code1)
            ast2 = ast.parse(code2)
            
            # Extract structural features from ASTs
            features1 = self._extract_ast_features_python(ast1)
            features2 = self._extract_ast_features_python(ast2)
            
            # Calculate similarity based on features
            return self._compare_ast_features(features1, features2)
            
        except SyntaxError as e:
            self.logger.debug(f"Syntax error in AST parsing: {e}")
            # If one or both have syntax errors, fall back to simple similarity
            return self._calculate_simple_structural_similarity(code1, code2)
        except Exception as e:
            self.logger.error(f"Python AST similarity failed: {e}")
            return self._calculate_simple_structural_similarity(code1, code2)

    def _extract_ast_features_python(self, tree: ast.AST) -> dict:
        """
        Extract structural features from a Python AST.
        
        Args:
            tree (ast.AST): The AST to analyze
            
        Returns:
            dict: Dictionary of AST features
        """
        features = {
            'node_types': [],
            'function_names': [],
            'class_names': [],
            'variable_names': [],
            'depth': 0,
            'node_count': 0
        }
        
        def visit_node(node, depth=0):
            features['node_count'] += 1
            features['depth'] = max(features['depth'], depth)
            features['node_types'].append(type(node).__name__)
            
            if isinstance(node, ast.FunctionDef):
                features['function_names'].append(node.name)
            elif isinstance(node, ast.ClassDef):
                features['class_names'].append(node.name)
            elif isinstance(node, ast.Name):
                features['variable_names'].append(node.id)
            
            for child in ast.iter_child_nodes(node):
                visit_node(child, depth + 1)
        
        visit_node(tree)
        
        # Convert lists to counts for comparison
        features['node_type_counts'] = {}
        for node_type in features['node_types']:
            features['node_type_counts'][node_type] = features['node_type_counts'].get(node_type, 0) + 1
        
        return features

    def _extract_ast_features_tree_sitter(self, code: str) -> dict:
        """
        Extract AST features using tree-sitter (fallback implementation).
        
        Args:
            code (str): Code to analyze
            
        Returns:
            dict: Dictionary of AST features
        """
        # This is a placeholder implementation
        # In a full implementation, this would use tree-sitter to parse the code
        # and extract structural features
        
        # For now, fall back to simple analysis
        return {
            'node_types': [],
            'function_names': [],
            'class_names': [],
            'variable_names': [],
            'depth': 0,
            'node_count': 0,
            'node_type_counts': {}
        }

    def _compare_ast_features(self, features1: dict, features2: dict) -> float:
        """
        Compare AST features to calculate similarity score.
        
        Args:
            features1 (dict): Features from first AST
            features2 (dict): Features from second AST
            
        Returns:
            float: Similarity score between 0.0 and 1.0
        """
        try:
            if not features1['node_type_counts'] and not features2['node_type_counts']:
                return 1.0
            
            if not features1['node_type_counts'] or not features2['node_type_counts']:
                return 0.0
            
            # Calculate Jaccard similarity for node types
            types1 = set(features1['node_type_counts'].keys())
            types2 = set(features2['node_type_counts'].keys())
            
            if not types1 and not types2:
                return 1.0
            
            intersection = len(types1.intersection(types2))
            union = len(types1.union(types2))
            
            if union == 0:
                return 1.0
            
            jaccard_similarity = intersection / union
            
            # Weight by structural similarity (depth, node count)
            depth_similarity = 1.0 - abs(features1['depth'] - features2['depth']) / max(features1['depth'], features2['depth'], 1)
            count_similarity = 1.0 - abs(features1['node_count'] - features2['node_count']) / max(features1['node_count'], features2['node_count'], 1)
            
            # Combine similarities
            ast_similarity = (0.5 * jaccard_similarity + 0.25 * depth_similarity + 0.25 * count_similarity)
            
            return max(0.0, min(1.0, ast_similarity))
            
        except Exception as e:
            self.logger.error(f"Error comparing AST features: {e}")
            return 0.0

    def _calculate_simple_structural_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate simple structural similarity as fallback for AST similarity.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: Structural similarity score between 0.0 and 1.0
        """
        try:
            # Count structural elements
            def count_structural_elements(code):
                elements = {
                    'functions': len(re.findall(r'\bdef\s+\w+', code)),
                    'classes': len(re.findall(r'\bclass\s+\w+', code)),
                    'if_statements': len(re.findall(r'\bif\s+', code)),
                    'for_loops': len(re.findall(r'\bfor\s+', code)),
                    'while_loops': len(re.findall(r'\bwhile\s+', code)),
                    'try_blocks': len(re.findall(r'\btry\s*:', code)),
                }
                return elements
            
            elements1 = count_structural_elements(code1)
            elements2 = count_structural_elements(code2)
            
            # Calculate similarity based on structural elements
            similarities = []
            for key in elements1:
                val1, val2 = elements1[key], elements2[key]
                if val1 == 0 and val2 == 0:
                    similarities.append(1.0)
                elif val1 == 0 or val2 == 0:
                    similarities.append(0.0)
                else:
                    similarities.append(1.0 - abs(val1 - val2) / max(val1, val2))
            
            return sum(similarities) / len(similarities) if similarities else 0.0
            
        except Exception as e:
            self.logger.error(f"Error in simple structural similarity: {e}")
            return 0.0

    def _calculate_dataflow_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate data-flow similarity based on variable usage patterns.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: Data-flow similarity score between 0.0 and 1.0
        """
        try:
            # Extract variable usage patterns
            patterns1 = self._extract_dataflow_patterns(code1)
            patterns2 = self._extract_dataflow_patterns(code2)
            
            # Compare patterns
            return self._compare_dataflow_patterns(patterns1, patterns2)
            
        except Exception as e:
            self.logger.error(f"Error in data-flow similarity calculation: {e}")
            # Fallback to simple variable similarity
            return self._calculate_simple_variable_similarity(code1, code2)

    def _extract_dataflow_patterns(self, code: str) -> dict:
        """
        Extract data-flow patterns from code.
        
        Args:
            code (str): Code to analyze
            
        Returns:
            dict: Dictionary of data-flow patterns
        """
        try:
            # Validate and clean code before parsing
            if not code or not code.strip():
                return {'assignments': [], 'reads': [], 'function_calls': [], 'variable_dependencies': {}}
            
            # Clean code to fix incomplete constructs that cause syntax errors
            lines = code.split('\n')
            cleaned_lines = []
            
            for i, line in enumerate(lines):
                stripped_line = line.strip()
                
                # Skip empty lines
                if not stripped_line:
                    cleaned_lines.append(line)
                    continue
                
                # Check for incomplete constructs that need indented blocks
                incomplete_constructs = [
                    'def ', 'class ', 'if ', 'elif ', 'else:', 'for ', 'while ', 
                    'try:', 'except', 'finally:', 'with ', 'async def ', 'async for ',
                    'async with '
                ]
                
                is_incomplete = False
                for construct in incomplete_constructs:
                    if (stripped_line.startswith(construct) and stripped_line.endswith(':')) or stripped_line == 'else:' or stripped_line == 'try:' or stripped_line == 'finally:':
                        is_incomplete = True
                        break
                
                if is_incomplete:
                    # Check if next line is properly indented (has function/block body)
                    has_indented_body = False
                    if i + 1 < len(lines):
                        next_line = lines[i + 1]
                        if next_line.strip() and (next_line.startswith('    ') or next_line.startswith('\t')):
                            has_indented_body = True
                    
                    cleaned_lines.append(line)
                    if not has_indented_body:
                        # Add appropriate indented content to make it valid
                        if stripped_line.startswith('def ') or stripped_line.startswith('async def '):
                            cleaned_lines.append('    pass')
                        elif stripped_line.startswith('class '):
                            cleaned_lines.append('    pass')
                        elif any(stripped_line.startswith(x) for x in ['if ', 'elif ', 'else:', 'for ', 'while ', 'async for ']):
                            cleaned_lines.append('    pass')
                        elif stripped_line == 'try:':
                            cleaned_lines.append('    pass')
                        elif stripped_line.startswith('except'):
                            cleaned_lines.append('    pass')
                        elif stripped_line == 'finally:':
                            cleaned_lines.append('    pass')
                        elif stripped_line.startswith('with ') or stripped_line.startswith('async with '):
                            cleaned_lines.append('    pass')
                        else:
                            cleaned_lines.append('    pass')
                else:
                    cleaned_lines.append(line)
            
            cleaned_code = '\n'.join(cleaned_lines)
            
            # Try to parse the cleaned code
            try:
                tree = ast.parse(cleaned_code)
            except SyntaxError as syntax_error:
                # If still failing, try more aggressive cleaning
                self.logger.debug(f"Syntax error after cleaning, trying aggressive mode: {syntax_error}")
                
                # Remove problematic lines and try again
                safe_lines = []
                for line in cleaned_lines:
                    stripped = line.strip()
                    # Skip lines that commonly cause issues
                    if (not stripped or 
                        stripped.startswith('#') or 
                        stripped in ['...', 'pass'] or
                        len(stripped) > 1000):  # Skip very long lines
                        continue
                    safe_lines.append('pass')  # Replace with safe statement
                
                if safe_lines:
                    try:
                        tree = ast.parse('\n'.join(safe_lines))
                    except:
                        # Final fallback - return empty patterns
                        return {'assignments': [], 'reads': [], 'function_calls': [], 'variable_dependencies': {}}
                else:
                    return {'assignments': [], 'reads': [], 'function_calls': [], 'variable_dependencies': {}}
            
            patterns = {
                'assignments': [],
                'reads': [],
                'function_calls': [],
                'variable_dependencies': {}
            }
            
            class DataFlowVisitor(ast.NodeVisitor):
                def visit_Assign(self, node):
                    try:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                patterns['assignments'].append(target.id)
                    except:
                        pass
                    self.generic_visit(node)
                
                def visit_Name(self, node):
                    try:
                        if isinstance(node.ctx, ast.Load):
                            patterns['reads'].append(node.id)
                    except:
                        pass
                    self.generic_visit(node)
                
                def visit_Call(self, node):
                    try:
                        if isinstance(node.func, ast.Name):
                            patterns['function_calls'].append(node.func.id)
                    except:
                        pass
                    self.generic_visit(node)
            
            visitor = DataFlowVisitor()
            visitor.visit(tree)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error extracting data-flow patterns: {e}")
            return {'assignments': [], 'reads': [], 'function_calls': [], 'variable_dependencies': {}}

    def _compare_dataflow_patterns(self, patterns1: dict, patterns2: dict) -> float:
        """
        Compare data-flow patterns to calculate similarity.
        
        Args:
            patterns1 (dict): Patterns from first code snippet
            patterns2 (dict): Patterns from second code snippet
            
        Returns:
            float: Data-flow similarity score between 0.0 and 1.0
        """
        try:
            similarities = []
            
            # Compare assignments
            assigns1 = set(patterns1['assignments'])
            assigns2 = set(patterns2['assignments'])
            if assigns1 or assigns2:
                intersection = len(assigns1.intersection(assigns2))
                union = len(assigns1.union(assigns2))
                similarities.append(intersection / union if union > 0 else 0.0)
            
            # Compare reads
            reads1 = set(patterns1['reads'])
            reads2 = set(patterns2['reads'])
            if reads1 or reads2:
                intersection = len(reads1.intersection(reads2))
                union = len(reads1.union(reads2))
                similarities.append(intersection / union if union > 0 else 0.0)
            
            # Compare function calls
            calls1 = set(patterns1['function_calls'])
            calls2 = set(patterns2['function_calls'])
            if calls1 or calls2:
                intersection = len(calls1.intersection(calls2))
                union = len(calls1.union(calls2))
                similarities.append(intersection / union if union > 0 else 0.0)
            
            return sum(similarities) / len(similarities) if similarities else 1.0
            
        except Exception as e:
            self.logger.error(f"Error comparing data-flow patterns: {e}")
            return 0.0

    def _calculate_simple_variable_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate simple variable similarity as fallback for data-flow similarity.
        
        Args:
            code1 (str): First code snippet
            code2 (str): Second code snippet
            
        Returns:
            float: Variable similarity score between 0.0 and 1.0
        """
        try:
            # Extract variable names using regex
            vars1 = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code1))
            vars2 = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code2))
            
            # Remove Python keywords
            python_keywords = {
                'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
                'elif', 'else', 'except', 'exec', 'finally', 'for', 'from', 'global',
                'if', 'import', 'in', 'is', 'lambda', 'not', 'or', 'pass', 'print',
                'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None'
            }
            
            vars1 = vars1 - python_keywords
            vars2 = vars2 - python_keywords
            
            if not vars1 and not vars2:
                return 1.0
            
            if not vars1 or not vars2:
                return 0.0
            
            intersection = len(vars1.intersection(vars2))
            union = len(vars1.union(vars2))
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Error in simple variable similarity: {e}")
            return 0.0

    def evaluate_all_metrics(self, generated_code: str, expected_code: str) -> CodeMetrics:
        """
        Calculate comprehensive code similarity metrics with configurable options and error handling.
        
        This is the primary public API method that calculates multiple similarity metrics
        between generated and expected code. The method respects configuration settings
        to enable/disable specific metrics and applies performance constraints.
        
        Metrics Calculated (if enabled):
        - **BLEU-4**: N-gram based similarity with 4-gram precision
        - **ROUGE-L**: Longest Common Subsequence recall-based similarity
        - **CodeBLEU**: AST-aware similarity considering syntactic structure
        - **Normalized Edit Distance**: Character-level similarity with normalization
        
        Features:
        - **Configuration-Aware**: Only calculates enabled metrics
        - **Performance Constraints**: Respects timeout and memory limits
        - **Graceful Degradation**: Uses fallback methods when primary calculations fail
        - **Resource Monitoring**: Adjusts strategy based on system resource availability
        - **Comprehensive Error Handling**: Continues evaluation even if individual metrics fail
        
        Args:
            generated_code (str): The generated code to evaluate. Can be empty string.
            expected_code (str): The expected/reference code. Can be empty string.
            
        Returns:
            CodeMetrics: Dataclass containing all calculated metrics and metadata:
                - code_bleu_score (float): CodeBLEU score (0.0-1.0, or -1.0 if failed/disabled)
                - bleu_4_score (float): BLEU-4 score (0.0-1.0, or -1.0 if failed/disabled)
                - rouge_l_score (float): ROUGE-L score (0.0-1.0, or -1.0 if failed/disabled)
                - normalized_edit_distance (float): Edit distance similarity (0.0-1.0, or -1.0 if failed/disabled)
                - calculation_errors (List[str]): List of error messages from failed calculations
                - preprocessing_successful (bool): Whether input preprocessing succeeded
        
        Raises:
            None: All exceptions are caught and handled gracefully. Check calculation_errors
                  in the returned CodeMetrics for details about any failures.
        
        Examples:
            Basic usage:
            ```python
            evaluator = CodeSimilarityEvaluator()
            metrics = evaluator.evaluate_all_metrics(
                "def add(a, b): return a + b",
                "def add(x, y): return x + y"
            )
            
            print(f"BLEU-4: {metrics.bleu_4_score:.3f}")
            print(f"ROUGE-L: {metrics.rouge_l_score:.3f}")
            
            if metrics.calculation_errors:
                print("Errors occurred:", metrics.calculation_errors)
            ```
            
            With error checking:
            ```python
            metrics = evaluator.evaluate_all_metrics(generated, expected)
            
            if not metrics.preprocessing_successful:
                print("Input preprocessing failed")
            
            # Check individual metrics
            if metrics.bleu_4_score >= 0:
                print(f"BLEU-4 successful: {metrics.bleu_4_score:.3f}")
            else:
                print("BLEU-4 calculation failed")
            
            # Calculate composite score from successful metrics
            composite = evaluator.calculate_composite_score(metrics)
            print(f"Overall similarity: {composite:.3f}")
            ```
        
        Note:
            - Scores range from 0.0 (no similarity) to 1.0 (perfect similarity)
            - Failed or disabled metrics return -1.0
            - Empty code inputs are handled gracefully (empty vs empty = 1.0)
            - Large code inputs are automatically truncated based on configuration
            - The method is thread-safe and can be called concurrently
        """
        # Initialize result with default failure values
        errors = []
        preprocessing_successful = True
        
        # Input validation and sanitization
        try:
            generated_code, expected_code = self._validate_and_sanitize_inputs(
                generated_code, expected_code
            )
        except Exception as e:
            self.logger.error(f"Input validation failed: {e}")
            errors.append(f"Input validation failed: {e}")
            preprocessing_successful = False
            # Use empty strings as fallback
            generated_code, expected_code = "", ""
        
        # Check system resources and adjust strategy accordingly
        resource_info = self._check_system_resources()
        if resource_info['should_use_fallbacks']:
            self.logger.warning(f"System resources constrained (Memory: {resource_info['available_memory_gb']:.2f}GB, "
                              f"CPU: {resource_info['cpu_percent']:.1f}%), using simplified calculations")
        
        # Initialize metrics with default failure values
        metrics = CodeMetrics(
            code_bleu_score=self.config.default_failed_metric_value,
            bleu_4_score=self.config.default_failed_metric_value,
            rouge_l_score=self.config.default_failed_metric_value,
            normalized_edit_distance=self.config.default_failed_metric_value,
            calculation_errors=[],
            preprocessing_successful=preprocessing_successful
        )
        
        # Calculate BLEU-4 score if enabled
        if self.config.enable_bleu_4:
            try:
                self.logger.debug("Calculating BLEU-4 score")
                # Use configuration timeout with resource adjustment
                timeout = min(self.config.ast_parsing_timeout_seconds, 15 if resource_info['should_use_fallbacks'] else 30)
                metrics.bleu_4_score = self._apply_timeout_constraint(
                    self._calculate_bleu_4_score, generated_code, expected_code, timeout_seconds=timeout
                )
                self.logger.debug(f"BLEU-4 score calculated: {metrics.bleu_4_score}")
            except TimeoutError as e:
                error_msg = f"BLEU-4 calculation timed out: {e}"
                self._log_metric_calculation_failure("BLEU-4", e, generated_code, expected_code)
                errors.append(error_msg)
                metrics.bleu_4_score = self.config.default_failed_metric_value
            except Exception as e:
                self._log_metric_calculation_failure("BLEU-4", e, generated_code, expected_code)
                errors.append(f"BLEU-4 calculation failed: {e}")
                metrics.bleu_4_score = self.config.default_failed_metric_value
        else:
            self.logger.debug("BLEU-4 calculation disabled by configuration")
        
        # Calculate ROUGE-L score if enabled
        if self.config.enable_rouge_l:
            try:
                if not ROUGE_AVAILABLE:
                    if self.config.log_missing_dependencies:
                        self.logger.warning("ROUGE library not available, using fallback similarity")
                    if self.config.fail_gracefully:
                        metrics.rouge_l_score = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("ROUGE-L: Library not available, used fallback similarity")
                    else:
                        raise ImportError("ROUGE library not available and fail_gracefully is disabled")
                else:
                    self.logger.debug("Calculating ROUGE-L score")
                    timeout = min(self.config.ast_parsing_timeout_seconds, 15 if resource_info['should_use_fallbacks'] else 30)
                    metrics.rouge_l_score = self._apply_timeout_constraint(
                        self._calculate_rouge_l_score, generated_code, expected_code, timeout_seconds=timeout
                    )
                    self.logger.debug(f"ROUGE-L score calculated: {metrics.rouge_l_score}")
            except TimeoutError as e:
                error_msg = f"ROUGE-L calculation timed out: {e}"
                self._log_metric_calculation_failure("ROUGE-L", e, generated_code, expected_code)
                errors.append(error_msg)
                if self.config.fail_gracefully:
                    try:
                        metrics.rouge_l_score = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("ROUGE-L: Used fallback similarity after timeout")
                    except Exception:
                        metrics.rouge_l_score = self.config.default_failed_metric_value
                else:
                    metrics.rouge_l_score = self.config.default_failed_metric_value
            except Exception as e:
                self._log_metric_calculation_failure("ROUGE-L", e, generated_code, expected_code)
                errors.append(f"ROUGE-L calculation failed: {e}")
                if self.config.fail_gracefully:
                    try:
                        metrics.rouge_l_score = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("ROUGE-L: Used fallback similarity after error")
                    except Exception:
                        metrics.rouge_l_score = self.config.default_failed_metric_value
                else:
                    metrics.rouge_l_score = self.config.default_failed_metric_value
        else:
            self.logger.debug("ROUGE-L calculation disabled by configuration")
        
        # Calculate Normalized Edit Distance if enabled
        if self.config.enable_edit_distance:
            try:
                if not EDITDISTANCE_AVAILABLE:
                    if self.config.log_missing_dependencies:
                        self.logger.warning("editdistance library not available, using fallback similarity")
                    if self.config.fail_gracefully:
                        metrics.normalized_edit_distance = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("Edit Distance: Library not available, used fallback similarity")
                    else:
                        raise ImportError("editdistance library not available and fail_gracefully is disabled")
                else:
                    self.logger.debug("Calculating Normalized Edit Distance")
                    timeout = min(self.config.ast_parsing_timeout_seconds, 15 if resource_info['should_use_fallbacks'] else 30)
                    metrics.normalized_edit_distance = self._apply_timeout_constraint(
                        self._calculate_normalized_edit_distance, generated_code, expected_code, timeout_seconds=timeout
                    )
                    self.logger.debug(f"Normalized Edit Distance calculated: {metrics.normalized_edit_distance}")
            except TimeoutError as e:
                error_msg = f"Edit Distance calculation timed out: {e}"
                self._log_metric_calculation_failure("Normalized Edit Distance", e, generated_code, expected_code)
                errors.append(error_msg)
                if self.config.fail_gracefully:
                    try:
                        metrics.normalized_edit_distance = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("Edit Distance: Used fallback similarity after timeout")
                    except Exception:
                        metrics.normalized_edit_distance = self.config.default_failed_metric_value
                else:
                    metrics.normalized_edit_distance = self.config.default_failed_metric_value
            except Exception as e:
                self._log_metric_calculation_failure("Normalized Edit Distance", e, generated_code, expected_code)
                errors.append(f"Normalized Edit Distance calculation failed: {e}")
                if self.config.fail_gracefully:
                    try:
                        metrics.normalized_edit_distance = self.calculate_fallback_similarity(generated_code, expected_code)
                        errors.append("Edit Distance: Used fallback similarity after error")
                    except Exception:
                        metrics.normalized_edit_distance = self.config.default_failed_metric_value
                else:
                    metrics.normalized_edit_distance = self.config.default_failed_metric_value
        else:
            self.logger.debug("Edit Distance calculation disabled by configuration")
        
        # Calculate CodeBLEU score if enabled
        if self.config.enable_code_bleu:
            try:
                self.logger.debug("Calculating CodeBLEU score")
                # CodeBLEU is more complex, so use longer timeout but still adjust for resources
                timeout = min(self.config.ast_parsing_timeout_seconds, 30 if resource_info['should_use_fallbacks'] else 60)
                metrics.code_bleu_score = self._apply_timeout_constraint(
                    self._calculate_code_bleu_score, generated_code, expected_code, timeout_seconds=timeout
                )
                self.logger.debug(f"CodeBLEU score calculated: {metrics.code_bleu_score}")
            except TimeoutError as e:
                error_msg = f"CodeBLEU calculation timed out: {e}"
                self._log_metric_calculation_failure("CodeBLEU", e, generated_code, expected_code)
                errors.append(error_msg)
                if self.config.fail_gracefully:
                    # Fallback to BLEU-4 score if available
                    if metrics.bleu_4_score >= 0.0:
                        metrics.code_bleu_score = metrics.bleu_4_score
                        errors.append("CodeBLEU: Used BLEU-4 score as fallback after timeout")
                    else:
                        try:
                            metrics.code_bleu_score = self.calculate_fallback_similarity(generated_code, expected_code)
                            errors.append("CodeBLEU: Used fallback similarity after timeout")
                        except Exception:
                            metrics.code_bleu_score = self.config.default_failed_metric_value
                else:
                    metrics.code_bleu_score = self.config.default_failed_metric_value
            except Exception as e:
                self._log_metric_calculation_failure("CodeBLEU", e, generated_code, expected_code)
                errors.append(f"CodeBLEU calculation failed: {e}")
                if self.config.fail_gracefully:
                    # Fallback to BLEU-4 score if available
                    if metrics.bleu_4_score >= 0.0:
                        metrics.code_bleu_score = metrics.bleu_4_score
                        errors.append("CodeBLEU: Used BLEU-4 score as fallback after error")
                    else:
                        try:
                            metrics.code_bleu_score = self.calculate_fallback_similarity(generated_code, expected_code)
                            errors.append("CodeBLEU: Used fallback similarity after error")
                        except Exception:
                            metrics.code_bleu_score = self.config.default_failed_metric_value
                else:
                    metrics.code_bleu_score = self.config.default_failed_metric_value
        else:
            self.logger.debug("CodeBLEU calculation disabled by configuration")
        
        # Set calculation errors
        metrics.calculation_errors = errors
        
        # Check if all enabled metrics failed and apply universal fallback
        enabled_metrics = self.config.get_enabled_metrics()
        successful_metrics = 0
        
        if "bleu_4" in enabled_metrics and metrics.bleu_4_score >= 0.0:
            successful_metrics += 1
        if "rouge_l" in enabled_metrics and metrics.rouge_l_score >= 0.0:
            successful_metrics += 1
        if "edit_distance" in enabled_metrics and metrics.normalized_edit_distance >= 0.0:
            successful_metrics += 1
        if "code_bleu" in enabled_metrics and metrics.code_bleu_score >= 0.0:
            successful_metrics += 1
        
        if successful_metrics == 0 and len(enabled_metrics) > 0:
            self.logger.error("All enabled metric calculations failed, applying universal fallback")
            if self.config.fail_gracefully:
                try:
                    fallback_metrics = self._get_fallback_metrics(generated_code, expected_code)
                    # Keep the original errors and add fallback info
                    fallback_metrics.calculation_errors = errors + fallback_metrics.calculation_errors
                    fallback_metrics.preprocessing_successful = preprocessing_successful
                    return fallback_metrics
                except Exception as e:
                    self.logger.critical(f"Universal fallback also failed: {e}")
                    # Return completely failed metrics as last resort
                    metrics.calculation_errors.append(f"Universal fallback failed: {e}")
        
        # Log summary of metric calculation
        self.logger.info(f"Metric calculation complete: {successful_metrics}/{len(enabled_metrics)} enabled metrics successful")
        if errors:
            self.logger.warning(f"Metric calculation errors: {len(errors)} errors occurred")
        
        return metrics
    
    def calculate_composite_score(self, metrics: CodeMetrics) -> float:
        """
        Calculate weighted composite score from individual metrics using configuration weights.
        
        This method combines multiple similarity metrics into a single composite score
        using the weights specified in the configuration. Only metrics that are enabled
        and have valid scores (>= 0) are included in the calculation.
        
        The composite score provides a single similarity measure that takes advantage
        of the strengths of different metrics:
        - BLEU-4: Good for lexical similarity
        - ROUGE-L: Good for sequence-based similarity
        - CodeBLEU: Good for structural/syntactic similarity
        - Edit Distance: Good for character-level similarity
        
        Args:
            metrics (CodeMetrics): CodeMetrics instance containing individual metric scores.
                                 Failed metrics (score = -1.0) are automatically excluded.
            
        Returns:
            float: Weighted composite score between 0.0 and 1.0, where:
                  - 0.0 indicates no similarity
                  - 1.0 indicates perfect similarity
                  - Returns 0.0 if no valid metrics are available
        
        Examples:
            ```python
            evaluator = CodeSimilarityEvaluator()
            metrics = evaluator.evaluate_all_metrics(generated_code, expected_code)
            
            # Calculate composite score
            composite = evaluator.calculate_composite_score(metrics)
            print(f"Overall similarity: {composite:.3f}")
            
            # Compare with individual metrics
            print(f"BLEU-4: {metrics.bleu_4_score:.3f}")
            print(f"ROUGE-L: {metrics.rouge_l_score:.3f}")
            print(f"CodeBLEU: {metrics.code_bleu_score:.3f}")
            print(f"Edit Distance: {metrics.normalized_edit_distance:.3f}")
            ```
            
            With custom weights:
            ```python
            from metrics_config import MetricsConfiguration
            
            # Emphasize structural similarity
            config = MetricsConfiguration(
                code_bleu_weight=0.6,  # Higher weight for AST-based similarity
                bleu_4_weight=0.2,
                rouge_l_weight=0.1,
                edit_distance_weight=0.1
            )
            
            evaluator = CodeSimilarityEvaluator(config=config)
            metrics = evaluator.evaluate_all_metrics(generated_code, expected_code)
            composite = evaluator.calculate_composite_score(metrics)
            ```
        
        Note:
            - Failed metrics (score = -1.0) are automatically excluded from calculation
            - Weights are automatically normalized if some metrics are disabled/failed
            - Returns 0.0 if all metrics failed or are disabled
            - The calculation is deterministic and reproducible
        """
        try:
            # Convert CodeMetrics to dictionary for compatibility
            metrics_dict = {
                "code_bleu_score": metrics.code_bleu_score,
                "bleu_4_score": metrics.bleu_4_score,
                "rouge_l_score": metrics.rouge_l_score,
                "normalized_edit_distance": metrics.normalized_edit_distance
            }
            
            # Use configuration's composite score calculation if available
            if hasattr(self.config, 'calculate_composite_score'):
                return self.config.calculate_composite_score(metrics_dict)
            else:
                # Fallback calculation for simple config objects
                total_score = 0.0
                total_weight = 0.0
                
                # Only include metrics that are enabled and have valid scores
                if getattr(self.config, 'enable_code_bleu', True) and metrics.code_bleu_score >= 0:
                    weight = getattr(self.config, 'code_bleu_weight', 0.25)
                    total_score += metrics.code_bleu_score * weight
                    total_weight += weight
                
                if getattr(self.config, 'enable_bleu_4', True) and metrics.bleu_4_score >= 0:
                    weight = getattr(self.config, 'bleu_4_weight', 0.25)
                    total_score += metrics.bleu_4_score * weight
                    total_weight += weight
                
                if getattr(self.config, 'enable_rouge_l', True) and metrics.rouge_l_score >= 0:
                    weight = getattr(self.config, 'rouge_l_weight', 0.25)
                    total_score += metrics.rouge_l_score * weight
                    total_weight += weight
                
                if getattr(self.config, 'enable_edit_distance', True) and metrics.normalized_edit_distance >= 0:
                    weight = getattr(self.config, 'edit_distance_weight', 0.25)
                    total_score += metrics.normalized_edit_distance * weight
                    total_weight += weight
                
                # Return weighted average if we have valid metrics
                if total_weight > 0:
                    return total_score / total_weight
                else:
                    return 0.0
                    
        except Exception as e:
            self.logger.error(f"Error calculating composite score: {e}")
            return 0.0
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current configuration for logging and debugging.
        
        Returns:
            Dict[str, Any]: Configuration summary
        """
        try:
            if hasattr(self.config, 'to_dict'):
                return self.config.to_dict()
            else:
                # Fallback for simple config objects
                return {
                    "enabled_metrics": getattr(self.config, 'get_enabled_metrics', lambda: ["unknown"])(),
                    "enable_code_bleu": getattr(self.config, 'enable_code_bleu', True),
                    "enable_bleu_4": getattr(self.config, 'enable_bleu_4', True),
                    "enable_rouge_l": getattr(self.config, 'enable_rouge_l', True),
                    "enable_edit_distance": getattr(self.config, 'enable_edit_distance', True),
                    "max_code_size_bytes": getattr(self.config, 'max_code_size_bytes', 1_000_000),
                    "ast_parsing_timeout_seconds": getattr(self.config, 'ast_parsing_timeout_seconds', 30),
                    "fail_gracefully": getattr(self.config, 'fail_gracefully', True)
                }
        except Exception as e:
            self.logger.error(f"Error getting configuration summary: {e}")
            return {"error": str(e)}
    
    def _validate_and_sanitize_inputs(self, generated_code: str, expected_code: str) -> tuple[str, str]:
        """
        Validate and sanitize input code strings with comprehensive error handling.
        Applies memory constraints, performance limits, and security sanitization.
        
        Args:
            generated_code (str): The generated code to validate
            expected_code (str): The expected code to validate
            
        Returns:
            tuple[str, str]: Validated and sanitized code strings
            
        Raises:
            ValueError: If inputs cannot be validated or sanitized
        """
        # Handle None inputs
        if generated_code is None:
            generated_code = ""
        if expected_code is None:
            expected_code = ""
        
        # Convert to strings if needed
        if not isinstance(generated_code, str):
            try:
                generated_code = str(generated_code)
            except Exception as e:
                raise ValueError(f"Failed to convert generated_code to string: {e}")
        
        if not isinstance(expected_code, str):
            try:
                expected_code = str(expected_code)
            except Exception as e:
                raise ValueError(f"Failed to convert expected_code to string: {e}")
        
        # Apply memory and performance constraints
        max_code_size = 1_000_000  # 1MB limit
        max_lines = 50_000  # Maximum number of lines
        
        # Check and apply size limits
        if len(generated_code) > max_code_size:
            self.logger.warning(f"Generated code too large ({len(generated_code)} chars), truncating to {max_code_size}")
            generated_code = generated_code[:max_code_size]
        
        if len(expected_code) > max_code_size:
            self.logger.warning(f"Expected code too large ({len(expected_code)} chars), truncating to {max_code_size}")
            expected_code = expected_code[:max_code_size]
        
        # Check line count limits
        try:
            gen_lines = generated_code.count('\n') + 1
            exp_lines = expected_code.count('\n') + 1
            
            if gen_lines > max_lines:
                self.logger.warning(f"Generated code has too many lines ({gen_lines}), truncating to {max_lines}")
                generated_code = '\n'.join(generated_code.split('\n')[:max_lines])
            
            if exp_lines > max_lines:
                self.logger.warning(f"Expected code has too many lines ({exp_lines}), truncating to {max_lines}")
                expected_code = '\n'.join(expected_code.split('\n')[:max_lines])
        except Exception as e:
            self.logger.warning(f"Error checking line counts: {e}")
        
        # Security and stability sanitization
        try:
            # Remove null bytes and other control characters that could cause issues
            control_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', 
                           '\x08', '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12', 
                           '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', 
                           '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x7f']
            
            for char in control_chars:
                generated_code = generated_code.replace(char, '')
                expected_code = expected_code.replace(char, '')
            
            # Normalize line endings to prevent cross-platform issues
            generated_code = generated_code.replace('\r\n', '\n').replace('\r', '\n')
            expected_code = expected_code.replace('\r\n', '\n').replace('\r', '\n')
            
            # Remove excessive consecutive whitespace that could cause performance issues
            import re
            generated_code = re.sub(r'\n{10,}', '\n' * 10, generated_code)  # Max 10 consecutive newlines
            expected_code = re.sub(r'\n{10,}', '\n' * 10, expected_code)
            
            generated_code = re.sub(r' {100,}', ' ' * 100, generated_code)  # Max 100 consecutive spaces
            expected_code = re.sub(r' {100,}', ' ' * 100, expected_code)
            
        except Exception as e:
            self.logger.warning(f"Error during security sanitization: {e}")
            # Continue with basic sanitization
            try:
                generated_code = generated_code.replace('\x00', '')
                expected_code = expected_code.replace('\x00', '')
            except Exception:
                pass  # If even basic sanitization fails, continue with original strings
        
        # Final validation
        try:
            # Ensure strings are valid UTF-8
            generated_code.encode('utf-8')
            expected_code.encode('utf-8')
        except UnicodeEncodeError as e:
            self.logger.warning(f"Unicode encoding issues detected: {e}")
            # Try to fix encoding issues
            try:
                generated_code = generated_code.encode('utf-8', errors='replace').decode('utf-8')
                expected_code = expected_code.encode('utf-8', errors='replace').decode('utf-8')
            except Exception:
                raise ValueError("Failed to handle Unicode encoding issues")
        
        return generated_code, expected_code
    
    def _check_dependencies(self) -> dict:
        """
        Check availability of optional dependencies and return status.
        
        Returns:
            dict: Dictionary with dependency availability status
        """
        dependencies = {
            'sacrebleu': True,
            'rouge_score': ROUGE_AVAILABLE,
            'editdistance': EDITDISTANCE_AVAILABLE,
            'tree_sitter': TREE_SITTER_AVAILABLE
        }
        
        # Test sacrebleu functionality
        try:
            import sacrebleu
            test_result = sacrebleu.sentence_bleu("test", ["test"])
            dependencies['sacrebleu'] = hasattr(test_result, 'score')
        except Exception:
            dependencies['sacrebleu'] = False
        
        return dependencies
    
    def _check_system_resources(self) -> dict:
        """
        Check available system resources to determine if metric calculations should proceed.
        
        Returns:
            dict: System resource information and recommendations
        """
        import psutil
        import os
        
        try:
            # Get memory information
            memory = psutil.virtual_memory()
            available_memory_gb = memory.available / (1024**3)
            
            # Get CPU information
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Check if we're in a memory-constrained environment
            memory_constrained = available_memory_gb < 1.0  # Less than 1GB available
            cpu_constrained = cpu_percent > 90  # CPU usage over 90%
            
            return {
                'available_memory_gb': available_memory_gb,
                'cpu_percent': cpu_percent,
                'memory_constrained': memory_constrained,
                'cpu_constrained': cpu_constrained,
                'should_use_fallbacks': memory_constrained or cpu_constrained
            }
        except ImportError:
            # psutil not available, assume normal resources
            self.logger.debug("psutil not available, cannot check system resources")
            return {
                'available_memory_gb': float('inf'),
                'cpu_percent': 0,
                'memory_constrained': False,
                'cpu_constrained': False,
                'should_use_fallbacks': False
            }
        except Exception as e:
            self.logger.warning(f"Error checking system resources: {e}")
            return {
                'available_memory_gb': float('inf'),
                'cpu_percent': 0,
                'memory_constrained': False,
                'cpu_constrained': False,
                'should_use_fallbacks': False
            }
    
    def _apply_timeout_constraint(self, func, *args, timeout_seconds: int = 30, **kwargs):
        """
        Apply timeout constraint to metric calculation functions.
        
        Args:
            func: Function to execute with timeout
            *args: Arguments for the function
            timeout_seconds (int): Timeout in seconds
            **kwargs: Keyword arguments for the function
            
        Returns:
            Result of function execution
            
        Raises:
            TimeoutError: If function execution exceeds timeout
        """
        import signal
        import time
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Function {func.__name__} exceeded {timeout_seconds}s timeout")
        
        # Set up timeout (Unix-like systems only, main thread only)
        try:
            import threading
            # Check if we're in the main thread - signals only work in main thread
            if threading.current_thread() is threading.main_thread():
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout_seconds)
                
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    signal.alarm(0)  # Cancel the alarm
                    signal.signal(signal.SIGALRM, old_handler)
            else:
                # In a thread - skip signal-based timeout and execute directly
                return func(*args, **kwargs)
                
        except (AttributeError, ValueError):
            # signal.SIGALRM not available (Windows) or signal error, fall back to simple execution
            return func(*args, **kwargs)
    
    def _get_fallback_metrics(self, generated_code: str, expected_code: str) -> CodeMetrics:
        """
        Calculate fallback metrics when primary methods fail.
        
        Args:
            generated_code (str): The generated code
            expected_code (str): The expected code
            
        Returns:
            CodeMetrics: Fallback metrics with basic similarity scores
        """
        errors = ["Using fallback metrics due to primary calculation failures"]
        
        try:
            # Simple character-based similarity as universal fallback
            fallback_score = self.calculate_fallback_similarity(generated_code, expected_code)
            
            return CodeMetrics(
                code_bleu_score=fallback_score,
                bleu_4_score=fallback_score,
                rouge_l_score=fallback_score,
                normalized_edit_distance=fallback_score,
                calculation_errors=errors,
                preprocessing_successful=True
            )
        except Exception as e:
            self.logger.error(f"Even fallback metrics failed: {e}")
            return CodeMetrics(
                code_bleu_score=0.0,
                bleu_4_score=0.0,
                rouge_l_score=0.0,
                normalized_edit_distance=0.0,
                calculation_errors=errors + [f"Fallback calculation failed: {e}"],
                preprocessing_successful=False
            )
    
    def _log_metric_calculation_failure(self, metric_name: str, error: Exception, 
                                      generated_code: str, expected_code: str):
        """
        Log detailed information about metric calculation failures.
        
        Args:
            metric_name (str): Name of the metric that failed
            error (Exception): The exception that occurred
            generated_code (str): The generated code being evaluated
            expected_code (str): The expected code being evaluated
        """
        self.logger.error(f"{metric_name} calculation failed: {error}")
        self.logger.debug(f"Generated code length: {len(generated_code)}")
        self.logger.debug(f"Expected code length: {len(expected_code)}")
        self.logger.debug(f"Generated code preview: {generated_code[:100]}...")
        self.logger.debug(f"Expected code preview: {expected_code[:100]}...")
        
        # Log dependency status for debugging
        if metric_name in ["ROUGE-L", "Normalized Edit Distance", "CodeBLEU"]:
            deps = self._check_dependencies()
            self.logger.debug(f"Dependency status: {deps}")

    def safe_calculate_bleu_score(self, generated_code: Union[str, None], expected_code: Union[str, None]) -> tuple[float, bool]:
        """
        Safely calculate BLEU score with fallback options.
        
        Args:
            generated_code (Union[str, None]): The generated code to evaluate
            expected_code (Union[str, None]): The expected/reference code
            
        Returns:
            tuple[float, bool]: (score, success_flag) where success_flag indicates if BLEU was used
        """
        # First try regular BLEU calculation
        try:
            if self.is_sacrebleu_available():
                score = self.calculate_bleu_score(generated_code, expected_code)
                return score, True
            else:
                self.logger.warning("sacrebleu not available, using fallback similarity")
                fallback_score = self.calculate_fallback_similarity(
                    generated_code or "", expected_code or ""
                )
                return fallback_score, False
        except Exception as e:
            self.logger.error(f"Error in safe BLEU calculation: {e}")
            try:
                fallback_score = self.calculate_fallback_similarity(
                    generated_code or "", expected_code or ""
                )
                return fallback_score, False
            except Exception as fallback_error:
                self.logger.error(f"Fallback similarity also failed: {fallback_error}")
                return 0.0, False