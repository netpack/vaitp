"""
Parallel Execution Module for VAITP Platform

This module implements the parallel execution engine for running multiple models
simultaneously across available GPUs with performance optimization.

Requirements implemented:
- 1.1, 1.2, 1.3: Parallel GPU execution with process isolation
- 1.6: Performance optimization and resource usage monitoring
- 3.3: Proper error handling and result serialization
- 3.4, 3.5: Resource monitoring and reporting capabilities
"""

import os
import json
import time
import signal
import pickle
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
import subprocess

from config import CODER_MODELS, LLM_N_CTX, LLM_N_THREADS, LLM_N_GPU_LAYERS, LLM_USE_MMAP, LLM_USE_MLOCK, LOCAL_LLM_SIGNAL_TIMEOUT
from utils import clear_memory
from main_orchestrator import PromptingStrategy, create_instruction_text, initialize_llm, TimeoutException, truncate_prompt_to_context_window
from performance_optimizer import PerformanceOptimizer, create_performance_optimizer
from monitoring_dashboard import RealTimeMonitor, DebugUtilities, create_monitoring_dashboard
from enhanced_logging import get_logging_manager, get_contextual_logger, LogContext

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class PlanData:
    """Serializable plan data for worker processes."""
    file_name: str
    original_code: str
    intended_vuln: Dict[str, Any]
    rag_context: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlanData':
        """Create PlanData from dictionary."""
        return cls(
            file_name=data['file_name'],
            original_code=data['original_code'],
            intended_vuln=data['intended_vuln'],
            rag_context=data.get('rag_context', '')
        )

@dataclass
class ModelResult:
    """Serializable result from worker process."""
    model_name: str
    gpu_id: int
    results: List[Dict[str, Any]]
    execution_time: float
    process_id: int
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'model_name': self.model_name,
            'gpu_id': self.gpu_id,
            'results': self.results,
            'execution_time': self.execution_time,
            'process_id': self.process_id,
            'error': self.error
        }

def detect_gpus() -> List[int]:
    """
    Detect available GPUs - supports both NVIDIA CUDA and Apple MPS.
    Returns list of GPU IDs or empty list if no GPUs available.
    """
    import platform
    import torch
    
    # Check for Apple MPS (macOS Metal Performance Shaders)
    if platform.system() == "Darwin":  # macOS
        try:
            if torch.backends.mps.is_available():
                logger.info("Detected Apple MPS (Metal Performance Shaders) - using MPS acceleration")
                return [0]  # MPS uses device 0
            else:
                logger.info("Apple MPS not available on this macOS system")
        except Exception as e:
            logger.warning(f"Error checking MPS availability: {e}")
    
    # Check for NVIDIA CUDA GPUs
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=index', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True
        )
        gpu_ids = [int(line.strip()) for line in result.stdout.strip().split('\n') if line.strip()]
        logger.info(f"Detected {len(gpu_ids)} NVIDIA CUDA GPUs: {gpu_ids}")
        return gpu_ids
    except (subprocess.CalledProcessError, FileNotFoundError):
        # nvidia-smi not available or failed
        pass
    
    # Check PyTorch CUDA availability as fallback
    try:
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_ids = list(range(gpu_count))
            logger.info(f"Detected {gpu_count} CUDA GPUs via PyTorch: {gpu_ids}")
            return gpu_ids
    except Exception as e:
        logger.warning(f"Error checking CUDA via PyTorch: {e}")
    
    logger.info("No GPUs detected, using CPU-only mode")
    return []

def get_gpu_memory_info(gpu_id: int) -> Dict[str, int]:
    """Get memory information for a specific GPU (NVIDIA CUDA or Apple MPS)."""
    import platform
    import torch
    
    # Handle Apple MPS
    if platform.system() == "Darwin" and torch.backends.mps.is_available():
        try:
            # MPS doesn't provide detailed memory info like CUDA
            # Return estimated values based on system memory
            import psutil
            total_memory = psutil.virtual_memory().total // (1024 * 1024)  # Convert to MB
            # Estimate GPU memory as a portion of system memory for MPS
            estimated_gpu_memory = min(total_memory // 4, 16384)  # Max 16GB estimate
            return {
                'total': estimated_gpu_memory,
                'used': 0,  # MPS doesn't provide used memory info
                'free': estimated_gpu_memory
            }
        except Exception as e:
            logger.warning(f"Error getting MPS memory info: {e}")
            return {'total': 8192, 'used': 0, 'free': 8192}  # Default fallback
    
    # Handle NVIDIA CUDA
    try:
        result = subprocess.run([
            'nvidia-smi', '--query-gpu=memory.total,memory.used,memory.free',
            '--format=csv,noheader,nounits', f'--id={gpu_id}'
        ], capture_output=True, text=True, check=True)
        
        memory_info = result.stdout.strip().split(', ')
        return {
            'total': int(memory_info[0]),
            'used': int(memory_info[1]), 
            'free': int(memory_info[2])
        }
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {'total': 0, 'used': 0, 'free': 0}

def timeout_handler(signum, frame):
    """Signal handler for timeout."""
    raise TimeoutException("Model execution timed out")

def run_generation_for_single_model(
    model_name: str, 
    gpu_id: int, 
    all_plans: List[Dict[str, Any]], 
    strategies_to_run: List[str],
    timeout_seconds: int = LOCAL_LLM_SIGNAL_TIMEOUT,
    performance_config: Optional[Dict[str, Any]] = None
) -> ModelResult:
    """
    Worker function that runs in a separate process.
    Executes one model against all plans and strategies on a dedicated GPU with performance monitoring.
    
    Args:
        model_name: Name of the model to execute
        gpu_id: GPU ID to assign to this process
        all_plans: List of plan dictionaries to process
        strategies_to_run: List of strategy names to execute
        timeout_seconds: Timeout for each model execution
        performance_config: Optional performance monitoring configuration
    
    Returns:
        ModelResult containing all results for this model
    """
    # CRITICAL: Pin this process to specific GPU
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)
    
    process_id = os.getpid()
    start_time = time.time()
    
    logger.info(f"Worker PID {process_id}: Starting {model_name} on GPU {gpu_id} with performance monitoring")
    
    try:
        # Convert strategy names back to enum objects
        strategy_objects = []
        for strategy_name in strategies_to_run:
            try:
                strategy_objects.append(PromptingStrategy[strategy_name])
            except KeyError:
                logger.warning(f"Unknown strategy: {strategy_name}, skipping")
                continue
        
        if not strategy_objects:
            raise ValueError(f"No valid strategies found in {strategies_to_run}")
        
        # Get model configuration
        if model_name not in CODER_MODELS:
            raise ValueError(f"Model {model_name} not found in CODER_MODELS")
        
        model_info = CODER_MODELS[model_name]
        model_path = model_info['path']
        model_format = model_info['format']
        model_type = "finetuned" if "finetuned" in model_name.lower() else "base"
        
        logger.info(f"Worker PID {process_id}: Loading model {model_name} (Format: {model_format})")
        
        # Aggressive memory cleanup before loading model
        try:
            from memory_manager import MemoryManager
            memory_manager = MemoryManager()
            
            # Force aggressive cleanup before loading
            memory_manager.cleanup_memory()
            
            # Check if this is a large model that needs special handling
            estimated_usage = memory_manager.estimate_model_memory_usage(model_name)
            memory_info = memory_manager.get_system_memory_info()
            
            logger.info(f"Worker PID {process_id}: Model {model_name} estimated usage: {estimated_usage:.1f}GB, "
                       f"available: {memory_info['available_gb']:.1f}GB")
            
            # For very large models, force CPU-only mode to be safe
            if estimated_usage > 12.0 and memory_info['available_gb'] < 8.0:
                logger.warning(f"Worker PID {process_id}: Large model {model_name} with limited memory, using CPU-only mode")
                os.environ['CUDA_VISIBLE_DEVICES'] = ''
                
        except Exception as e:
            logger.warning(f"Worker PID {process_id}: Memory management failed: {e}")
        
        # Initialize the model
        coder_llm = initialize_llm(model_path)
        if not coder_llm:
            raise RuntimeError(f"Failed to load model from {model_path}")
        
        all_results = []
        
        # Process each plan
        for plan_data_dict in all_plans:
            plan_data = PlanData.from_dict(plan_data_dict)
            
            # Process each strategy for this plan
            for strategy in strategy_objects:
                logger.info(f"Worker PID {process_id}: Processing {plan_data.file_name} with {strategy.name}")
                
                try:
                    # Create instruction text
                    instruction_prompt = create_instruction_text(
                        strategy=strategy,
                        original_code=plan_data.original_code,
                        intended_vuln_details=plan_data.intended_vuln,
                        rag_context=plan_data.rag_context
                    )
                    
                    # Assemble final prompt based on model type and format
                    final_prompt = _create_final_prompt(
                        instruction_prompt, 
                        plan_data.original_code, 
                        model_type, 
                        model_format
                    )
                    
                    # Set timeout signal
                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(timeout_seconds)
                    
                    # Call the LLM with robust error handling
                    stop_tokens = ["\n```", "</s>", "[/INST]", "</code>", "<|eot_id|>", "<|im_end|>"]
                    
                    # Try multiple inference configurations for robustness
                    inference_configs = [
                        {"max_tokens": 1024, "temperature": 0.1, "name": "standard"},
                        {"max_tokens": 512, "temperature": 0.0, "name": "reduced_tokens"},
                        {"max_tokens": 256, "temperature": 0.0, "name": "minimal_tokens"}
                    ]
                    
                    result = None
                    last_inference_error = None
                    
                    for config in inference_configs:
                        try:
                            # Truncate prompt to fit context window
                            truncated_prompt = truncate_prompt_to_context_window(final_prompt, coder_llm, config["max_tokens"], model_path)
                            
                            result = coder_llm(
                                prompt=truncated_prompt,
                                max_tokens=config["max_tokens"],
                                stop=stop_tokens,
                                echo=False,
                                temperature=config["temperature"]
                            )
                            logger.debug(f"Worker PID {process_id}: Inference successful with {config['name']} config")
                            break
                        except Exception as inference_error:
                            last_inference_error = inference_error
                            error_msg = str(inference_error)
                            
                            # Check for specific decode errors
                            if "llama_decode returned -3" in error_msg or "decode" in error_msg.lower():
                                logger.warning(f"Worker PID {process_id}: Decode error with {config['name']} config, trying next: {error_msg}")
                                # For decode errors, try to continue with a fallback result
                                if config == inference_configs[-1]:
                                    logger.error(f"Worker PID {process_id}: All configs failed with decode errors, using fallback")
                                    result = {
                                        'choices': [{'text': f'# Error: Model decode failure\n# Original code returned due to decode error\n{plan_data.original_code}'}]
                                    }
                                    break
                            else:
                                logger.warning(f"Worker PID {process_id}: Inference error with {config['name']} config: {error_msg}")
                                # If this was the last config, we'll handle it in the outer exception handler
                                if config == inference_configs[-1]:
                                    raise inference_error
                            continue
                    
                    if result is None:
                        raise RuntimeError(f"All inference configurations failed. Last error: {last_inference_error}")
                    
                    # Clear timeout
                    signal.alarm(0)
                    
                    # Extract generated code
                    choices = result.get('choices', [])
                    generated_code = choices[0].get('text', '').lstrip() if choices and isinstance(choices[0], dict) else ''
                    
                    # Store result
                    all_results.append({
                        "model_full_name": model_name,
                        "file_name": plan_data.file_name,
                        "original_code": plan_data.original_code,
                        "intended_vuln": plan_data.intended_vuln,
                        "rag_context": plan_data.rag_context,
                        "prompt_strategy": strategy.name,
                        "final_prompt": final_prompt,
                        "generated_code": generated_code,
                        "static_report": {},
                        "static_confirmation_status": "pending",
                        "static_interpreter_justification": "pending"
                    })
                    
                except TimeoutException:
                    logger.error(f"Worker PID {process_id}: Timeout for {plan_data.file_name} with {strategy.name}")
                    all_results.append({
                        "model_full_name": model_name,
                        "file_name": plan_data.file_name,
                        "original_code": plan_data.original_code,
                        "intended_vuln": plan_data.intended_vuln,
                        "rag_context": plan_data.rag_context,
                        "prompt_strategy": strategy.name,
                        "final_prompt": "",
                        "generated_code": "",
                        "static_report": {"error": "Timeout during generation"},
                        "static_confirmation_status": "FAILURE (Timeout)",
                        "static_interpreter_justification": "Model execution timed out"
                    })
                except Exception as e:
                    logger.error(f"Worker PID {process_id}: Error processing {plan_data.file_name} with {strategy.name}: {e}")
                    all_results.append({
                        "model_full_name": model_name,
                        "file_name": plan_data.file_name,
                        "original_code": plan_data.original_code,
                        "intended_vuln": plan_data.intended_vuln,
                        "rag_context": plan_data.rag_context,
                        "prompt_strategy": strategy.name,
                        "final_prompt": "",
                        "generated_code": "",
                        "static_report": {"error": str(e)},
                        "static_confirmation_status": "FAILURE (Generation Error)",
                        "static_interpreter_justification": f"Generation failed: {e}"
                    })
                finally:
                    signal.alarm(0)  # Ensure timeout is cleared
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        logger.info(f"Worker PID {process_id}: {model_name} completed {len(all_results)} tasks in {execution_time:.2f}s")
        
        return ModelResult(
            model_name=model_name,
            gpu_id=gpu_id,
            results=all_results,
            execution_time=execution_time,
            process_id=process_id,
            error=None
        )
        
    except Exception as e:
        end_time = time.time()
        execution_time = end_time - start_time
        
        logger.error(f"Worker PID {process_id}: {model_name} failed with error: {e}")
        
        return ModelResult(
            model_name=model_name,
            gpu_id=gpu_id,
            results=[],
            execution_time=execution_time,
            process_id=process_id,
            error=str(e)
        )
    
    finally:
        # Aggressive cleanup to prevent memory leaks
        try:
            if 'coder_llm' in locals():
                del coder_llm
            
            # Force garbage collection
            import gc
            gc.collect()
            
            # Clear GPU caches if available
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                    torch.mps.empty_cache()
            except Exception:
                pass
            
            clear_memory()
            signal.alarm(0)
            
            logger.debug(f"Worker PID {process_id}: Aggressive cleanup completed for {model_name}")
        except Exception as cleanup_error:
            logger.warning(f"Worker PID {process_id}: Error during cleanup: {cleanup_error}")

def _create_final_prompt(instruction_prompt: str, original_code: str, model_type: str, model_format: str) -> str:
    """
    Create the final formatted prompt based on model type and format.
    
    Args:
        instruction_prompt: The core instruction text
        original_code: The original code to modify
        model_type: "finetuned" or "base"
        model_format: "llama3" or "chatml"
    
    Returns:
        Formatted prompt string
    """
    if model_type == "finetuned":
        if model_format == 'llama3':
            return (
                f"<|start_header_id|>system<|end_header_id|>\n\n"
                f"You are a helpful assistant that only outputs Python code.<|eot_id|>\n"
                f"<|start_header_id|>user<|end_header_id|>\n\n"
                f"{instruction_prompt} _BREAK_ {original_code.strip()}\n<|eot_id|>\n"
                f"<|start_header_id|>assistant<|end_header_id|>\n\n"
                f"```python"
            )
        else:  # chatml
            return (
                f"<|im_start|>system\n"
                f"You are a helpful assistant that only outputs Python code.<|im_end|>\n"
                f"<|im_start|>user\n"
                f"{instruction_prompt} _BREAK_ {original_code.strip()}<|im_end|>\n"
                f"<|im_start|>assistant\n"
                f"```python"
            )
    else:  # model_type is "base"
        if model_format == 'llama3':
            return (
                f"<|start_header_id|>system<|end_header_id|>\n\n"
                f"You are a helpful assistant that only outputs Python code.<|eot_id|>\n"
                f"<|start_header_id|>user<|end_header_id|>\n\n"
                f"{instruction_prompt}\n\n"
                f"Original Code:\n```python\n{original_code.strip()}\n```\n<|eot_id|>\n"
                f"<|start_header_id|>assistant<|end_header_id|>\n\n"
                f"```python"
            )
        else:  # chatml
            return (
                f"<|im_start|>system\n"
                f"You are a helpful assistant that only outputs Python code.<|im_end|>\n"
                f"<|im_start|>user\n"
                f"{instruction_prompt}\n\n"
                f"Original Code:\n```python\n{original_code.strip()}\n```\n<|im_end|>\n"
                f"<|im_start|>assistant\n"
                f"```python"
            )

class ResultAggregator:
    """Aggregates results from multiple worker processes."""
    
    def __init__(self):
        self.results = []
        self.execution_metadata = {}
    
    def add_model_results(self, model_result: ModelResult) -> None:
        """Add results from a completed model worker."""
        self.results.extend(model_result.results)
        self.execution_metadata[model_result.model_name] = {
            'gpu_id': model_result.gpu_id,
            'process_id': model_result.process_id,
            'execution_time': model_result.execution_time,
            'error': model_result.error,
            'task_count': len(model_result.results)
        }
    
    def get_combined_results(self) -> List[Dict[str, Any]]:
        """Get all results in the same format as sequential execution."""
        return self.results
    
    def get_execution_report(self) -> Dict[str, Any]:
        """Generate metadata about the parallel execution."""
        total_tasks = sum(meta['task_count'] for meta in self.execution_metadata.values())
        successful_models = len([meta for meta in self.execution_metadata.values() if meta['error'] is None])
        total_time = max(meta['execution_time'] for meta in self.execution_metadata.values()) if self.execution_metadata else 0
        
        return {
            'total_models': len(self.execution_metadata),
            'successful_models': successful_models,
            'total_tasks': total_tasks,
            'wall_clock_time': total_time,
            'gpu_assignments': {model: meta['gpu_id'] for model, meta in self.execution_metadata.items()},
            'process_assignments': {model: meta['process_id'] for model, meta in self.execution_metadata.items()},
            'model_execution_times': {model: meta['execution_time'] for model, meta in self.execution_metadata.items()},
            'errors': {model: meta['error'] for model, meta in self.execution_metadata.items() if meta['error']}
        }

class ParallelOrchestrator:
    """
    Manages parallel execution of Phase 2 using ProcessPoolExecutor.
    Distributes models across available GPUs and tracks progress with performance optimization.
    
    Requirements implemented:
    - 1.1, 1.4, 1.5: GPU detection, parallel execution, progress tracking
    - 1.6: Performance optimization and resource usage monitoring
    - 3.1, 3.2, 3.4, 3.5: Error handling, resource cleanup, timeout mechanisms
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ParallelOrchestrator.
        
        Args:
            config: Configuration dictionary with performance optimization settings
        """
        self.config = config or {}
        self.available_gpus = self._detect_gpus()
        self.result_aggregator = ResultAggregator()
        
        # Configuration parameters
        self.timeout_per_model = self.config.get('timeout_per_model', 300)
        self.max_retries = self.config.get('max_retries', 1)
        
        # Performance optimization
        self.enable_optimization = self.config.get('enable_performance_optimization', True)
        self.performance_optimizer = None
        if self.enable_optimization:
            self.performance_optimizer = create_performance_optimizer(self.config)
        
        # Monitoring and debugging
        self.enable_monitoring = self.config.get('enable_real_time_monitoring', True)
        self.monitor = None
        self.debug_utils = None
        if self.enable_monitoring:
            self.monitor = create_monitoring_dashboard(self.config.get('monitoring_interval', 1.0))
            self.debug_utils = DebugUtilities(self.monitor)
        
        # Enhanced logging
        self.logging_manager = get_logging_manager()
        self.execution_logger = get_contextual_logger('vaitp.parallel_execution')
        
        logger.info(f"ParallelOrchestrator initialized with {len(self.available_gpus)} GPUs, "
                   f"optimization {'enabled' if self.enable_optimization else 'disabled'}, "
                   f"monitoring {'enabled' if self.enable_monitoring else 'disabled'}")
    
    def _detect_gpus(self) -> List[int]:
        """Detect available GPUs and return list of GPU IDs."""
        return detect_gpus()
    
    def run_parallel_phase2(
        self, 
        coders_to_run: List[str], 
        all_plans: List[Dict[str, Any]], 
        strategies_to_run: List[str],
        max_workers: Optional[int] = None,
        progress_callback: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute Phase 2 generation in parallel across multiple GPUs with performance optimization.
        
        Args:
            coders_to_run: List of model names to execute
            all_plans: List of plan dictionaries to process
            strategies_to_run: List of strategy names to execute
            max_workers: Maximum number of parallel workers (optimized automatically if None)
            progress_callback: Optional callback for progress updates
        
        Returns:
            List of all results in the same format as sequential execution
        """
        if not coders_to_run:
            raise ValueError("No models specified for execution")
        
        if not all_plans:
            raise ValueError("No plans provided for processing")
        
        if not strategies_to_run:
            raise ValueError("No strategies specified for execution")
        
        # Start performance monitoring
        if self.performance_optimizer:
            self.performance_optimizer.start_monitoring(self.available_gpus)
        
        # Start real-time monitoring
        if self.monitor:
            self.monitor.start_monitoring(self.available_gpus)
        
        # Log execution start
        self.logging_manager.log_execution_start({
            'models': coders_to_run,
            'strategies': strategies_to_run,
            'plans_count': len(all_plans),
            'gpus_available': len(self.available_gpus),
            'optimization_enabled': self.enable_optimization,
            'monitoring_enabled': self.enable_monitoring
        })
        
        # Determine optimal number of workers
        if max_workers is None:
            if self.performance_optimizer:
                max_workers = self.performance_optimizer.get_optimal_worker_count(
                    self.available_gpus, len(coders_to_run)
                )
            else:
                max_workers = len(self.available_gpus) if self.available_gpus else 1
        else:
            max_workers = min(max_workers, len(self.available_gpus)) if self.available_gpus else 1
        
        logger.info(f"Starting parallel execution with {max_workers} workers (optimized)")
        logger.info(f"Models: {coders_to_run}")
        logger.info(f"Plans: {len(all_plans)}")
        logger.info(f"Strategies: {strategies_to_run}")
        
        self.execution_logger.info(
            f"Parallel execution initialized with {max_workers} workers",
            models=coders_to_run,
            plans_count=len(all_plans),
            strategies=strategies_to_run,
            max_workers=max_workers
        )
        
        if progress_callback:
            progress_callback(f"Initializing optimized parallel execution with {max_workers} workers...")
        
        start_time = time.time()
        
        try:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Submit all model tasks with optimized GPU assignment
                future_to_model = {}
                for i, model_name in enumerate(coders_to_run):
                    # Use performance optimizer for GPU assignment if available
                    if self.performance_optimizer:
                        gpu_id = self.performance_optimizer.get_optimal_gpu_assignment(
                            self.available_gpus, model_name
                        )
                    else:
                        gpu_id = self.available_gpus[i % len(self.available_gpus)] if self.available_gpus else 0
                    
                    logger.info(f"Submitting {model_name} to GPU {gpu_id}")
                    
                    # Register process with monitoring
                    if self.monitor:
                        total_tasks = len(all_plans) * len(strategies_to_run)
                        self.monitor.register_process(model_name, -1, gpu_id, total_tasks)  # PID will be updated in worker
                    
                    # Log GPU assignment
                    self.execution_logger.log_gpu_assignment(model_name, gpu_id, -1)
                    
                    future = executor.submit(
                        run_generation_for_single_model,
                        model_name=model_name,
                        gpu_id=gpu_id,
                        all_plans=all_plans,
                        strategies_to_run=strategies_to_run,
                        timeout_seconds=self.timeout_per_model,
                        performance_config=self.config if self.enable_optimization else None
                    )
                    future_to_model[future] = model_name
                
                # Collect results as they complete
                completed_models = 0
                total_models = len(coders_to_run)
                
                for future in as_completed(future_to_model):
                    model_name = future_to_model[future]
                    completed_models += 1
                    
                    try:
                        model_result = future.result()
                        self.result_aggregator.add_model_results(model_result)
                        
                        # Register process completion with performance optimizer
                        if self.performance_optimizer:
                            task_results = {
                                'completed_tasks': len([r for r in model_result.results if not r.get('static_report', {}).get('error')]),
                                'failed_tasks': len([r for r in model_result.results if r.get('static_report', {}).get('error')])
                            }
                            self.performance_optimizer.register_process_end(model_name, task_results)
                        
                        # Register completion with monitoring
                        if self.monitor:
                            self.monitor.complete_process(model_name, True, None)
                        
                        # Log process completion
                        self.execution_logger.log_process_completion(
                            model_name, model_result.process_id, model_result.execution_time, True
                        )
                        
                        logger.info(f"✅ Completed {model_name} ({completed_models}/{total_models}) - "
                                  f"GPU {model_result.gpu_id}, PID {model_result.process_id}, "
                                  f"{model_result.execution_time:.2f}s, {len(model_result.results)} results")
                        
                        if progress_callback:
                            progress_callback(f"Completed {model_name} ({completed_models}/{total_models})")
                    
                    except Exception as e:
                        logger.error(f"❌ Model {model_name} failed: {e}")
                        
                        # Register failed process with performance optimizer
                        if self.performance_optimizer:
                            self.performance_optimizer.register_process_end(model_name, {
                                'completed_tasks': 0,
                                'failed_tasks': 1
                            })
                        
                        # Register failure with monitoring
                        if self.monitor:
                            self.monitor.complete_process(model_name, False, str(e))
                        
                        # Log process failure
                        self.execution_logger.log_process_completion(
                            model_name, -1, 0.0, False, str(e)
                        )
                        
                        # Create a failed result for consistency
                        failed_result = ModelResult(
                            model_name=model_name,
                            gpu_id=-1,
                            results=[],
                            execution_time=0.0,
                            process_id=-1,
                            error=str(e)
                        )
                        self.result_aggregator.add_model_results(failed_result)
                        
                        if progress_callback:
                            progress_callback(f"Failed {model_name} ({completed_models}/{total_models}): {e}")
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Generate execution report with performance data
            execution_report = self.result_aggregator.get_execution_report()
            execution_report['total_wall_clock_time'] = total_time
            
            # Add performance optimization data
            if self.performance_optimizer:
                performance_report = self.performance_optimizer.get_performance_report()
                execution_report['performance_data'] = performance_report
                
                # Get optimization recommendations
                recommendations = self.performance_optimizer.get_optimization_recommendations()
                if recommendations:
                    execution_report['optimization_recommendations'] = recommendations
                    logger.info(f"Performance recommendations: {len(recommendations)} suggestions available")
            
            # Add monitoring data
            if self.monitor:
                monitoring_status = self.monitor.get_current_status()
                execution_report['monitoring_data'] = monitoring_status
                
                # Generate debug report if there were failures
                if execution_report['errors']:
                    debug_report_path = f"debug_report_{int(time.time())}.json"
                    self.debug_utils.generate_debug_report(debug_report_path)
                    execution_report['debug_report_path'] = debug_report_path
                    logger.info(f"Debug report generated: {debug_report_path}")
            
            # Log execution completion
            self.logging_manager.log_execution_end(total_time, {
                'successful_models': execution_report['successful_models'],
                'total_models': execution_report['total_models'],
                'total_tasks': execution_report['total_tasks'],
                'errors': len(execution_report['errors']) if execution_report['errors'] else 0
            })
            
            logger.info("=== Parallel Execution Summary ===")
            logger.info(f"Total time: {total_time:.2f}s")
            logger.info(f"Models processed: {execution_report['successful_models']}/{execution_report['total_models']}")
            logger.info(f"Total tasks: {execution_report['total_tasks']}")
            logger.info(f"GPU assignments: {execution_report['gpu_assignments']}")
            
            if execution_report['errors']:
                logger.warning(f"Errors encountered: {execution_report['errors']}")
            
            # Print monitoring summary if available
            if self.debug_utils:
                self.debug_utils.print_status_summary()
            
            if progress_callback:
                progress_callback(f"Parallel execution completed in {total_time:.2f}s")
            
            return self.result_aggregator.get_combined_results()
        
        except Exception as e:
            logger.error(f"Parallel execution failed: {e}")
            if progress_callback:
                progress_callback(f"Parallel execution failed: {e}")
            raise
        
        finally:
            # Stop performance monitoring
            if self.performance_optimizer:
                self.performance_optimizer.stop_monitoring()
            
            # Stop real-time monitoring
            if self.monitor:
                self.monitor.stop_monitoring()
                
                # Save monitoring report
                monitoring_report_path = f"monitoring_report_{int(time.time())}.json"
                self.monitor.save_monitoring_report(monitoring_report_path)
                logger.info(f"Monitoring report saved: {monitoring_report_path}")
    
    def get_execution_metadata(self) -> Dict[str, Any]:
        """Get metadata about the last execution."""
        return self.result_aggregator.get_execution_report()
    
    def get_performance_report(self) -> Optional[Dict[str, Any]]:
        """Get performance report from the optimizer."""
        if self.performance_optimizer:
            return self.performance_optimizer.get_performance_report()
        return None
    
    def save_performance_report(self, output_path: str) -> None:
        """Save performance report to file."""
        if self.performance_optimizer:
            self.performance_optimizer.save_performance_report(output_path)
            logger.info(f"Performance report saved to: {output_path}")
        else:
            logger.warning("Performance optimizer not enabled, no report to save")
    
    def save_monitoring_report(self, output_path: str) -> None:
        """Save monitoring report to file."""
        if self.monitor:
            self.monitor.save_monitoring_report(output_path)
            logger.info(f"Monitoring report saved to: {output_path}")
        else:
            logger.warning("Real-time monitoring not enabled, no report to save")
    
    def get_debug_analysis(self) -> Optional[Dict[str, Any]]:
        """Get debug analysis of failed processes."""
        if self.debug_utils:
            return self.debug_utils.analyze_failed_processes()
        return None
    
    def cleanup(self) -> None:
        """Cleanup resources and reset state."""
        if self.performance_optimizer:
            self.performance_optimizer.cleanup()
        if self.monitor:
            self.monitor.stop_monitoring()
        self.result_aggregator = ResultAggregator()
        logger.info("ParallelOrchestrator cleaned up")

def create_parallel_orchestrator(config: Optional[Dict[str, Any]] = None) -> ParallelOrchestrator:
    """
    Factory function to create a ParallelOrchestrator instance.
    
    Args:
        config: Optional configuration dictionary
    
    Returns:
        Configured ParallelOrchestrator instance
    """
    return ParallelOrchestrator(config)