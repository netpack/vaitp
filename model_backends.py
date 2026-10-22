"""
Model backend abstraction layer for supporting multiple inference engines.

This module provides a unified interface for different model backends including
llama-cpp-python and oLLM, enabling seamless switching between backends based
on hardware capabilities and model requirements.
"""

import logging
import time
import psutil
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from ollm_logging import get_ollm_logger
from config import LOCAL_LLM_TIMEOUT, HEALTH_CHECK_TIMEOUT


@dataclass
class ModelInfo:
    """Information about a loaded model."""
    name: str
    backend: str
    parameters: Optional[int] = None
    context_length: Optional[int] = None
    loaded: bool = False
    device: Optional[str] = None
    memory_usage_mb: Optional[float] = None


class ModelBackend(ABC):
    """Abstract base class for model backends."""
    
    def __init__(self):
        self.model_info = ModelInfo(name="", backend=self.__class__.__name__)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def load_model(self, model_path: str, config: Dict[str, Any]) -> bool:
        """
        Load a model with given configuration.
        
        Args:
            model_path: Path to the model file
            config: Configuration dictionary with backend-specific parameters
            
        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate text from prompt.
        
        Args:
            prompt: Input text prompt
            **kwargs: Generation parameters (max_tokens, temperature, etc.)
            
        Returns:
            str: Generated text
        """
        pass
    
    @abstractmethod
    def unload_model(self) -> None:
        """Unload the current model and free resources."""
        pass
    
    @abstractmethod
    def get_model_info(self) -> ModelInfo:
        """
        Get information about the loaded model.
        
        Returns:
            ModelInfo: Information about the current model
        """
        pass
    
    def is_loaded(self) -> bool:
        """Check if a model is currently loaded."""
        return self.model_info.loaded


class ModelBackendFactory:
    """Factory for creating appropriate model backends."""
    
    _backends = {}
    
    @classmethod
    def register_backend(cls, name: str, backend_class: type):
        """
        Register a backend class with a name.
        
        Args:
            name: Backend identifier
            backend_class: Backend class that implements ModelBackend
        """
        if not issubclass(backend_class, ModelBackend):
            raise ValueError(f"Backend class must inherit from ModelBackend")
        cls._backends[name] = backend_class
    
    @classmethod
    def create_backend(cls, backend_type: str = "llamacpp") -> ModelBackend:
        """
        Create a model backend instance.
        
        Args:
            backend_type: Type of backend to create ("llamacpp", "ollm")
            
        Returns:
            ModelBackend: Instance of the requested backend
            
        Raises:
            ValueError: If backend_type is not supported
        """
        if backend_type not in cls._backends:
            available = list(cls._backends.keys())
            raise ValueError(f"Unknown backend type '{backend_type}'. Available: {available}")
        
        backend_class = cls._backends[backend_type]
        return backend_class()
    
    @classmethod
    def get_available_backends(cls) -> list:
        """Get list of available backend types."""
        return list(cls._backends.keys())
    
    @classmethod
    def is_backend_available(cls, backend_type: str) -> bool:
        """Check if a backend type is available."""
        return backend_type in cls._backends


# Base backend implementations will be registered by their respective modules
# This allows for optional dependencies and graceful degradation


class LlamaCppBackend(ModelBackend):
    """Backend wrapper for llama-cpp-python functionality."""
    
    def __init__(self):
        super().__init__()
        self.llm = None
        self.model_path = None
        self.config = None
    
    def load_model(self, model_path: str, config: Dict[str, Any]) -> bool:
        """
        Load a model using llama-cpp-python.
        
        Args:
            model_path: Path to the GGUF model file
            config: Configuration dictionary with llama-cpp parameters
            
        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        ollm_logger = get_ollm_logger()
        start_time = time.time()
        
        # Get memory usage before loading
        memory_before = psutil.virtual_memory().used / (1024 * 1024)
        
        try:
            from llama_cpp import Llama
            
            self.logger.info(f"Loading model with llama-cpp-python: {model_path}")
            self.logger.debug(f"Configuration: {config}")
            
            # Store configuration for reference
            self.model_path = model_path
            self.config = config.copy()
            
            # Create Llama instance with provided configuration
            self.llm = Llama(model_path=model_path, **config)
            
            # Update model info
            self.model_info.name = model_path
            self.model_info.backend = "LlamaCppBackend"
            self.model_info.loaded = True
            self.model_info.device = config.get('device', 'cpu')
            
            # Try to extract context length from config
            self.model_info.context_length = config.get('n_ctx', None)
            
            # Get memory usage after loading
            memory_after = psutil.virtual_memory().used / (1024 * 1024)
            loading_time = (time.time() - start_time) * 1000
            
            # Log the successful loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="llamacpp",
                config=config,
                success=True,
                loading_time_ms=loading_time,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
                device=config.get('device', 'cpu')
            )
            
            self.logger.info(f"Successfully loaded model: {model_path}")
            return True
            
        except ImportError as e:
            loading_time = (time.time() - start_time) * 1000
            error_msg = f"llama-cpp-python not available: {e}"
            
            # Log the failed loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="llamacpp",
                config=config,
                success=False,
                loading_time_ms=loading_time,
                error_message=error_msg,
                memory_before_mb=memory_before
            )
            
            self.logger.error(error_msg)
            return False
        except Exception as e:
            loading_time = (time.time() - start_time) * 1000
            error_msg = f"Failed to load model with llama-cpp-python: {e}"
            
            # Log the failed loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="llamacpp",
                config=config,
                success=False,
                loading_time_ms=loading_time,
                error_message=error_msg,
                memory_before_mb=memory_before
            )
            
            self.logger.error(error_msg)
            return False
    
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate text using llama-cpp-python.
        
        Args:
            prompt: Input text prompt
            **kwargs: Generation parameters (max_tokens, temperature, etc.)
            
        Returns:
            str: Generated text
            
        Raises:
            RuntimeError: If no model is loaded
        """
        if not self.llm:
            raise RuntimeError("No model loaded. Call load_model() first.")
        
        ollm_logger = get_ollm_logger()
        start_time = time.time()
        
        # Monitor resource usage during inference
        with ollm_logger.monitor_operation("llamacpp_inference") as monitor:
            try:
                self.logger.debug(f"Generating text with parameters: {kwargs}")
                
                # Call llama-cpp-python with the prompt and parameters
                response = self.llm(prompt, **kwargs)
                
                # Extract text from response
                generated_text = ""
                if isinstance(response, dict) and "choices" in response:
                    if response["choices"] and "text" in response["choices"][0]:
                        generated_text = response["choices"][0]["text"]
                        self.logger.debug(f"Generated {len(generated_text)} characters")
                    else:
                        self.logger.warning("No text found in response choices")
                else:
                    self.logger.warning(f"Unexpected response format: {type(response)}")
                    generated_text = str(response) if response else ""
                
                # Calculate inference metrics
                inference_time = (time.time() - start_time) * 1000
                peak_usage = monitor.get_peak_usage()
                
                # Log the inference operation
                ollm_logger.log_inference_operation(
                    model_name=self.model_info.name,
                    backend_type="llamacpp",
                    prompt_length=len(prompt),
                    generated_length=len(generated_text),
                    inference_time_ms=inference_time,
                    parameters=kwargs,
                    memory_peak_mb=peak_usage.get('peak_memory_mb'),
                    ssd_io_mb=peak_usage.get('total_ssd_read_mb', 0) + peak_usage.get('total_ssd_write_mb', 0)
                )
                
                return generated_text
                    
            except Exception as e:
                inference_time = (time.time() - start_time) * 1000
                error_msg = f"Text generation failed: {e}"
                
                # Log the failed inference
                ollm_logger.log_inference_operation(
                    model_name=self.model_info.name,
                    backend_type="llamacpp",
                    prompt_length=len(prompt),
                    generated_length=0,
                    inference_time_ms=inference_time,
                    parameters=kwargs,
                    error_message=error_msg
                )
                
                self.logger.error(error_msg)
                raise
    
    def unload_model(self) -> None:
        """Unload the current model and free resources."""
        if self.llm:
            self.logger.info("Unloading llama-cpp-python model")
            # llama-cpp-python doesn't have explicit unload, just remove reference
            self.llm = None
            
        # Reset model info
        self.model_info.loaded = False
        self.model_info.name = ""
        self.model_path = None
        self.config = None
        
        # Force garbage collection to free memory
        import gc
        gc.collect()
    
    def get_model_info(self) -> ModelInfo:
        """Get information about the loaded model."""
        if self.llm and self.model_path:
            # Try to get additional info if available
            try:
                # Estimate memory usage if possible
                import psutil
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                self.model_info.memory_usage_mb = memory_mb
            except (ImportError, Exception):
                # psutil not available or other error, skip memory info
                pass
        
        return self.model_info
    
    def get_raw_llm(self):
        """Get the underlying llama-cpp-python Llama instance for compatibility."""
        return self.llm


# Register the LlamaCppBackend
ModelBackendFactory.register_backend("llamacpp", LlamaCppBackend)


class OLLMBackend(ModelBackend):
    """Backend wrapper for oLLM memory-efficient inference."""
    
    def __init__(self):
        super().__init__()
        self.inference = None
        self.model_path = None
        self.config = None
    
    def load_model(self, model_path: str, config: Dict[str, Any]) -> bool:
        """
        Load a model using oLLM.
        
        Args:
            model_path: Path to the model file
            config: Configuration dictionary with oLLM parameters
            
        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        ollm_logger = get_ollm_logger()
        start_time = time.time()
        
        # Get memory usage before loading
        memory_before = psutil.virtual_memory().used / (1024 * 1024)
        
        try:
            from ollm import Inference
            
            self.logger.info(f"Loading model with oLLM: {model_path}")
            self.logger.debug(f"Configuration: {config}")
            
            # Store configuration for reference
            self.model_path = model_path
            self.config = config.copy()
            
            # Extract oLLM-specific parameters
            device = config.get('device', 'auto')
            logging_enabled = config.get('logging', True)
            
            # Create oLLM Inference instance
            self.inference = Inference(
                model_name=model_path,
                device=device,
                logging=logging_enabled
            )
            
            # Update model info
            self.model_info.name = model_path
            self.model_info.backend = "OLLMBackend"
            self.model_info.loaded = True
            self.model_info.device = device
            
            # Try to extract context length from config if available
            self.model_info.context_length = config.get('context_length', None)
            
            # Get memory usage after loading
            memory_after = psutil.virtual_memory().used / (1024 * 1024)
            loading_time = (time.time() - start_time) * 1000
            
            # Log the successful loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="ollm",
                config=config,
                success=True,
                loading_time_ms=loading_time,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
                device=device
            )
            
            self.logger.info(f"Successfully loaded model with oLLM: {model_path}")
            return True
            
        except ImportError as e:
            loading_time = (time.time() - start_time) * 1000
            error_msg = f"oLLM not available: {e}"
            
            # Log the failed loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="ollm",
                config=config,
                success=False,
                loading_time_ms=loading_time,
                error_message=error_msg,
                memory_before_mb=memory_before
            )
            
            self.logger.error(error_msg)
            return False
        except Exception as e:
            loading_time = (time.time() - start_time) * 1000
            error_msg = f"Failed to load model with oLLM: {e}"
            
            # Log the failed loading
            ollm_logger.log_model_loading(
                model_name=model_path,
                model_path=model_path,
                backend_type="ollm",
                config=config,
                success=False,
                loading_time_ms=loading_time,
                error_message=error_msg,
                memory_before_mb=memory_before
            )
            
            self.logger.error(error_msg)
            return False
    
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate text using oLLM.
        
        Args:
            prompt: Input text prompt
            **kwargs: Generation parameters (max_tokens, temperature, etc.)
            
        Returns:
            str: Generated text
            
        Raises:
            RuntimeError: If no model is loaded
        """
        if not self.inference:
            raise RuntimeError("No model loaded. Call load_model() first.")
        
        ollm_logger = get_ollm_logger()
        start_time = time.time()
        
        # Monitor resource usage during inference with enhanced SSD monitoring
        with ollm_logger.monitor_operation("ollm_inference") as monitor:
            try:
                self.logger.debug(f"Generating text with parameters: {kwargs}")
                
                # Convert llama-cpp parameters to oLLM format
                max_tokens = kwargs.get('max_tokens', 1024)
                temperature = kwargs.get('temperature', 0.7)
                top_p = kwargs.get('top_p', 0.9)
                
                # Map max_tokens to max_length for oLLM
                ollm_params = {
                    'max_length': max_tokens,
                    'temperature': temperature,
                    'top_p': top_p
                }
                
                # Add other oLLM-specific parameters if present
                if 'do_sample' in kwargs:
                    ollm_params['do_sample'] = kwargs['do_sample']
                if 'repetition_penalty' in kwargs:
                    ollm_params['repetition_penalty'] = kwargs['repetition_penalty']
                
                self.logger.debug(f"Mapped oLLM parameters: {ollm_params}")
                
                # Call oLLM generate method
                response = self.inference.generate(prompt=prompt, **ollm_params)
                
                # oLLM typically returns the generated text directly
                generated_text = ""
                if isinstance(response, str):
                    generated_text = response
                elif isinstance(response, dict) and 'text' in response:
                    generated_text = response['text']
                elif isinstance(response, dict) and 'generated_text' in response:
                    generated_text = response['generated_text']
                else:
                    self.logger.warning(f"Unexpected oLLM response format: {type(response)}")
                    generated_text = str(response) if response else ""
                
                # Calculate inference metrics
                inference_time = (time.time() - start_time) * 1000
                peak_usage = monitor.get_peak_usage()
                
                # Log the inference operation with enhanced oLLM-specific metrics
                ollm_logger.log_inference_operation(
                    model_name=self.model_info.name,
                    backend_type="ollm",
                    prompt_length=len(prompt),
                    generated_length=len(generated_text),
                    inference_time_ms=inference_time,
                    parameters=ollm_params,  # Log the mapped parameters
                    memory_peak_mb=peak_usage.get('peak_memory_mb'),
                    ssd_io_mb=peak_usage.get('total_ssd_read_mb', 0) + peak_usage.get('total_ssd_write_mb', 0)
                )
                
                self.logger.debug(f"Generated {len(generated_text)} characters")
                return generated_text
                    
            except Exception as e:
                inference_time = (time.time() - start_time) * 1000
                error_msg = f"Text generation failed: {e}"
                
                # Log the failed inference
                ollm_logger.log_inference_operation(
                    model_name=self.model_info.name,
                    backend_type="ollm",
                    prompt_length=len(prompt),
                    generated_length=0,
                    inference_time_ms=inference_time,
                    parameters=kwargs,
                    error_message=error_msg
                )
                
                self.logger.error(error_msg)
                raise
    
    def unload_model(self) -> None:
        """Unload the current model and free resources."""
        if self.inference:
            self.logger.info("Unloading oLLM model")
            # oLLM may have cleanup methods, try to call them
            try:
                if hasattr(self.inference, 'cleanup'):
                    self.inference.cleanup()
                elif hasattr(self.inference, 'unload'):
                    self.inference.unload()
            except Exception as e:
                self.logger.debug(f"oLLM cleanup error (ignored): {e}")
            
            self.inference = None
            
        # Reset model info
        self.model_info.loaded = False
        self.model_info.name = ""
        self.model_path = None
        self.config = None
        
        # Force garbage collection to free memory
        import gc
        gc.collect()
    
    def get_model_info(self) -> ModelInfo:
        """Get information about the loaded model."""
        if self.inference and self.model_path:
            # Try to get additional info if available
            try:
                # Estimate memory usage if possible
                import psutil
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                self.model_info.memory_usage_mb = memory_mb
            except (ImportError, Exception):
                # psutil not available or other error, skip memory info
                pass
            
            # Try to get model-specific info from oLLM if available
            try:
                if hasattr(self.inference, 'get_model_info'):
                    ollm_info = self.inference.get_model_info()
                    if isinstance(ollm_info, dict):
                        self.model_info.parameters = ollm_info.get('parameters', None)
                        self.model_info.context_length = ollm_info.get('context_length', None)
            except Exception as e:
                self.logger.debug(f"Could not get oLLM model info: {e}")
        
        return self.model_info
    
    def get_raw_inference(self):
        """Get the underlying oLLM Inference instance for compatibility."""
        return self.inference


# Register the OLLMBackend
ModelBackendFactory.register_backend("ollm", OLLMBackend)


class OllamaBackend(ModelBackend):
    """Backend wrapper for Ollama HTTP API inference."""

    def __init__(self):
        super().__init__()
        self.model_name = None
        self.config = None
        self._base_url = "http://localhost:11434"

    def load_model(self, model_path: str, config: Dict[str, Any]) -> bool:
        """
        'Load' a model via Ollama — just verifies it's available.
        model_path is treated as the Ollama model name (e.g. 'deepseek-r1:14b').
        """
        import requests
        start_time = time.time()

        try:
            self.model_name = config.get('model_name', model_path)
            self.config = config.copy()
            self._base_url = config.get('base_url', "http://localhost:11434")

            # Verify Ollama is running and model is available
            # Retry with generous timeout — Ollama may be slow after long generations
            resp = None
            for _attempt in range(3):
                try:
                    resp = requests.get(f"{self._base_url}/api/tags", timeout=HEALTH_CHECK_TIMEOUT)
                    resp.raise_for_status()
                    break
                except (requests.ReadTimeout, requests.ConnectionError) as retry_err:
                    if _attempt < 2:
                        self.logger.warning(f"Ollama health check attempt {_attempt + 1}/3 failed ({retry_err}), retrying in 5s...")
                        time.sleep(5)
                    else:
                        raise
            available = [m["name"] for m in resp.json().get("models", [])]
            matched = any(self.model_name in name or name.startswith(self.model_name) for name in available)

            if not matched:
                self.logger.error(f"Model '{self.model_name}' not found in Ollama. Available: {available}")
                return False

            self.model_info.name = self.model_name
            self.model_info.backend = "OllamaBackend"
            self.model_info.loaded = True
            self.model_info.device = "ollama"
            self.model_info.context_length = config.get('n_ctx', 8192)

            loading_time = (time.time() - start_time) * 1000
            self.logger.info(f"Ollama model '{self.model_name}' verified in {loading_time:.0f}ms")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to Ollama: {e}")
            return False

    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using Ollama HTTP API."""
        import requests

        if not self.model_name:
            raise RuntimeError("No model loaded. Call load_model() first.")

        max_tokens = kwargs.get('max_tokens', 2048)
        temperature = kwargs.get('temperature', 0.3)
        top_p = kwargs.get('top_p', 0.9)
        stop = kwargs.get('stop', [])
        # echo is a llama-cpp param, ignored for Ollama

        # For reasoning models, boost token budget for <think> blocks
        effective_max_tokens = max(max_tokens, 4096)

        # Filter out stop tokens that could appear inside <think> blocks
        safe_stop = [s for s in stop if '```' not in s] if stop else []

        options = {
            "num_predict": effective_max_tokens,
            "temperature": temperature,
            "top_p": top_p,
        }
        if safe_stop:
            options["stop"] = safe_stop

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }

        try:
            resp = requests.post(
                f"{self._base_url}/api/generate",
                json=payload,
                timeout=LOCAL_LLM_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            # For deepseek-r1: Ollama separates thinking from response.
            # We only want the final response (visible output after </think>).
            # If response is empty, fall back to thinking content.
            response = data.get("response", "")
            thinking = data.get("thinking", "")
            
            if response:
                return response
            elif thinking:
                self.logger.warning(f"Ollama: Model produced only thinking, no visible response. Using thinking as fallback.")
                return thinking
            return ""
        except Exception as e:
            self.logger.error(f"Ollama API error: {e}")
            raise

    def unload_model(self) -> None:
        """Ollama manages its own model lifecycle."""
        self.model_info.loaded = False
        self.model_info.name = ""
        self.model_name = None
        self.config = None

    def get_model_info(self) -> ModelInfo:
        """Get information about the loaded model."""
        return self.model_info


# Register the OllamaBackend
ModelBackendFactory.register_backend("ollama", OllamaBackend)


class ModelWrapper:
    """
    Wrapper class that maintains llama-cpp-python interface compatibility.
    
    This class wraps any ModelBackend and provides the same interface as
    llama-cpp-python's Llama class, ensuring backward compatibility with
    existing code.
    """
    
    def __init__(self, backend: ModelBackend, backend_type: str):
        """
        Initialize the wrapper with a backend.
        
        Args:
            backend: The ModelBackend instance to wrap
            backend_type: Type of backend ("llamacpp", "ollm", etc.)
        """
        self.backend = backend
        self.backend_type = backend_type
        self.logger = logging.getLogger(f"{__name__}.ModelWrapper")
    
    def __call__(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """
        Generate text maintaining llama-cpp-python interface.
        
        Args:
            prompt: Input text prompt
            **kwargs: Generation parameters
            
        Returns:
            Dict with llama-cpp-python compatible format:
            {
                'choices': [{'text': generated_text}],
                'usage': {'total_tokens': approximate_count},
                'backend': backend_type
            }
        """
        try:
            # Generate text using the backend
            generated_text = self.backend.generate(prompt, **kwargs)
            
            # Calculate approximate token count (rough estimation)
            # This is a simple approximation - real token counting would require tokenizer
            approximate_tokens = len(generated_text.split()) + len(prompt.split())
            
            # Return in llama-cpp-python compatible format
            response = {
                'choices': [{'text': generated_text}],
                'usage': {'total_tokens': approximate_tokens},
                'backend': self.backend_type
            }
            
            self.logger.debug(f"Generated response with {approximate_tokens} tokens (approx)")
            return response
            
        except Exception as e:
            self.logger.error(f"Text generation failed: {e}")
            # Return empty response in case of error
            return {
                'choices': [{'text': ''}],
                'usage': {'total_tokens': 0},
                'backend': self.backend_type,
                'error': str(e)
            }
    
    def get_backend_info(self) -> Dict[str, Any]:
        """
        Get information about the wrapped backend.
        
        Returns:
            Dict containing backend information
        """
        model_info = self.backend.get_model_info()
        return {
            'backend_type': self.backend_type,
            'model_name': model_info.name,
            'loaded': model_info.loaded,
            'device': model_info.device,
            'parameters': model_info.parameters,
            'context_length': model_info.context_length,
            'memory_usage_mb': model_info.memory_usage_mb
        }
    
    def unload(self):
        """Unload the model (compatibility method)."""
        self.backend.unload_model()
    
    def is_loaded(self) -> bool:
        """Check if model is loaded (compatibility method)."""
        return self.backend.is_loaded()
    
    def get_raw_backend(self) -> ModelBackend:
        """Get the underlying backend instance."""
        return self.backend
    
    # Additional compatibility methods for llama-cpp-python interface
    def generate(self, prompt: str, **kwargs) -> str:
        """Direct text generation method."""
        return self.backend.generate(prompt, **kwargs)
    
    def __repr__(self) -> str:
        """String representation of the wrapper."""
        model_info = self.backend.get_model_info()
        return f"ModelWrapper(backend={self.backend_type}, model={model_info.name}, loaded={model_info.loaded})"