"""
Refactored Phase 2 execution with parallel support.

This module provides the enhanced run_phase2_execute_coders function that uses
the ParallelOrchestrator for multi-GPU execution while maintaining backward compatibility.
"""

import os
import json
import pickle
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from rich.console import Console
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from config import CODER_MODELS, PROMPTS_DIR, LOCAL_LLM_SIGNAL_TIMEOUT
from main_orchestrator import PromptingStrategy, setup_logging, truncate_prompt_to_context_window
from orchestration.injection_agents import StaticAnalysisAgent
from parallel_execution import ParallelOrchestrator, detect_gpus
from utils import clear_memory

console = Console()
logger = logging.getLogger(__name__)

def run_phase2_execute_coders_parallel(args, prompts_dir=None):
    """
    Enhanced Phase 2: Executes code generation and analysis with parallel GPU support.
    
    This function maintains backward compatibility while adding parallel execution capabilities.
    When multiple GPUs are available and multiple models are specified, it will use
    parallel execution. Otherwise, it falls back to sequential execution.
    
    Args:
        args: Argument namespace containing execution parameters
        prompts_dir: Optional custom prompts directory. If None, uses model-specific directory.
    """
    logger = setup_logging()
    console.print(Rule("[bold green]:dna: VAITP: Phase 2 - Coder Execution & Analysis (Enhanced)[/bold green]"))
    
    # Determine prompts directory
    if prompts_dir is None:
        # For Phase 2, we need to use the prompts generated in Phase 1
        # Try to find the Phase 1 prompts directory for the same model
        if hasattr(args, 'coder') and args.coder:
            model_key = args.coder[0] if isinstance(args.coder, list) else args.coder
            experiment_name = getattr(args, 'experiment_name', None)
            
            # For CVE2023 experiments, look for Phase 1 directory
            if experiment_name and 'phase2' in experiment_name:
                # Map phase2 experiment names to phase1 directories
                if 'deepthink' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_deepthink'
                elif 'llama' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_llama'
                else:
                    phase1_experiment = experiment_name.replace('phase2', 'phase1')
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, phase1_experiment)
            else:
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, experiment_name)
        else:
            prompts_dir = PROMPTS_DIR
    
    console.print(f"[bold blue]:file_folder: Using prompts directory: {prompts_dir}[/bold blue]")
    
    gen_results_path = os.path.join(prompts_dir, "generated_results.pkl")
    analyzed_results_path = os.path.join(prompts_dir, "analyzed_results.pkl")

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    )

    # --- PHASE 2a: GENERATION ---
    if args.stage in ['generate', 'all']:
        console.print(Rule("[bold blue]:fire: Phase 2a: Generating All Code Snippets (Enhanced GPU Task)[/bold blue]"))
        
        # Load plan files
        plan_files = [os.path.join(prompts_dir, f) for f in os.listdir(prompts_dir) if f.endswith('_plan.json')]
        
        if not plan_files:
            console.print("[bold red]❌ No plan files found. Please run Phase 1 first.[/bold red]")
            return
        
        # Determine models to run
        if 'all' in args.coder: 
            coders_to_run = list(CODER_MODELS.keys())
        else: 
            coders_to_run = [name for name in args.coder if name in CODER_MODELS]
        
        # Memory management: Force sequential execution for large models to prevent crashes
        try:
            from memory_manager import MemoryManager
            memory_manager = MemoryManager()
            memory_info = memory_manager.get_system_memory_info()
            
            # Check if we have large models that need sequential execution
            large_models = []
            for model_name in coders_to_run:
                estimated_usage = memory_manager.estimate_model_memory_usage(model_name)
                if estimated_usage > 6.0:  # Models >6GB need special handling
                    large_models.append(model_name)
            
            if large_models:
                console.print(f"[yellow]⚠️  Memory Management: {len(large_models)} large models detected. "
                            f"Will use sequential execution with aggressive cleanup.[/yellow]")
                console.print(f"[blue]📊 System Memory: {memory_info['used_gb']:.1f}GB used, "
                            f"{memory_info['available_gb']:.1f}GB available ({memory_info['percent']:.1f}%)[/blue]")
            else:
                console.print(f"[green]✅ All models are small enough for normal execution[/green]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Memory check failed: {e}. Proceeding with all models.[/yellow]")

        # Determine strategies to run
        if 'all' in args.strategy:
            strategies_to_run = [s.name for s in PromptingStrategy]
        else:
            strategies_to_run = [s for s in args.strategy if s in [strategy.name for strategy in PromptingStrategy]]

        if not strategies_to_run:
            console.print(f"[bold red]❌ Error: No valid strategies found in '{args.strategy}'.[/bold red]")
            return
        
        console.print(f":notebook: Running with {len(strategies_to_run)} strategies: {strategies_to_run}")
        console.print(f":robot: Running with {len(coders_to_run)} models: {coders_to_run}")
        
        # Load all plans into memory
        all_plans = []
        for plan_file_path in plan_files:
            with open(plan_file_path, 'r') as f:
                plan_data = json.load(f)
                all_plans.append(plan_data)
        
        console.print(f":file_folder: Loaded {len(all_plans)} plans from Phase 1")
        
        # Determine execution strategy
        available_gpus = detect_gpus()
        use_parallel = _should_use_parallel_execution(coders_to_run, available_gpus, args)
        
        if use_parallel:
            console.print(f"[bold green]:rocket: Using parallel execution with {len(available_gpus)} GPUs[/bold green]")
            all_results = _run_parallel_generation(
                coders_to_run, all_plans, strategies_to_run, available_gpus, args
            )
        else:
            console.print(f"[bold yellow]:turtle: Using sequential execution (fallback mode)[/bold yellow]")
            all_results = _run_sequential_generation(
                coders_to_run, all_plans, strategies_to_run, args
            )
        
        # Save results
        console.print(f":floppy_disk: Saving {len(all_results)} generated snippets to [cyan]{gen_results_path}[/cyan]")
        with open(gen_results_path, "wb") as f:
            pickle.dump(all_results, f)
        console.print("✅ Generation complete and progress saved.")

    # --- PHASE 2b: STATIC ANALYSIS ---
    if args.stage in ['analyze', 'all']:
        console.print(Rule("[bold blue]:flashlight: Phase 2b: Running Static Analysis in Parallel (CPU Task)[/bold blue]"))
        if not os.path.exists(gen_results_path):
            console.print(f"[bold red]:x: Generated results not found. Please run the 'generate' stage first.[/bold red]")
            return
        
        with open(gen_results_path, "rb") as f:
            all_results = pickle.load(f)
        
        _run_static_analysis_phase(all_results, analyzed_results_path, progress_columns)

    # --- PHASE 2c/d: EVALUATION & LOGGING ---
    if args.stage in ['evaluate', 'all']:
        from main_orchestrator import run_evaluation_stage
        run_evaluation_stage(args, results_pickle_path=analyzed_results_path)

def _should_use_parallel_execution(coders_to_run: List[str], available_gpus: List[int], args) -> bool:
    """
    Determine whether to use parallel execution based on available resources and configuration.
    
    Args:
        coders_to_run: List of model names to execute
        available_gpus: List of available GPU IDs
        args: Arguments namespace
    
    Returns:
        True if parallel execution should be used, False otherwise
    """
    # Check if user explicitly disabled parallel execution
    if hasattr(args, 'num_gpus') and args.num_gpus == 1:
        return False
    
    # Need at least 2 models to benefit from parallelization
    if len(coders_to_run) < 2:
        return False
    
    # Need at least 1 GPU for parallel execution (can still parallelize on single GPU)
    # But prefer multiple GPUs for best performance
    if not available_gpus:
        logger.info("No GPUs detected, using sequential execution")
        return False
    
    # Check for large models that need sequential execution to prevent memory issues
    try:
        from memory_manager import MemoryManager
        memory_manager = MemoryManager()
        
        large_models = []
        for model_name in coders_to_run:
            estimated_usage = memory_manager.estimate_model_memory_usage(model_name)
            if estimated_usage > 8.0:  # Models >8GB are considered large
                large_models.append(model_name)
        
        # If we have large models, force sequential execution for safety
        if large_models:
            logger.info(f"Large models detected ({len(large_models)} models >8GB), forcing sequential execution for memory safety")
            return False
            
    except Exception as e:
        logger.warning(f"Memory check failed: {e}, proceeding with parallel execution")
    
    # Use parallel execution if we have multiple models and at least one GPU
    return True

def _run_parallel_generation(
    coders_to_run: List[str], 
    all_plans: List[Dict[str, Any]], 
    strategies_to_run: List[str],
    available_gpus: List[int],
    args
) -> List[Dict[str, Any]]:
    """
    Run generation phase using parallel execution.
    
    Args:
        coders_to_run: List of model names to execute
        all_plans: List of plan dictionaries
        strategies_to_run: List of strategy names
        available_gpus: List of available GPU IDs
        args: Arguments namespace
    
    Returns:
        List of all results from parallel execution
    """
    # Create configuration for ParallelOrchestrator
    config = {
        'timeout_per_model': getattr(args, 'timeout_per_model', 300),
        'max_retries': getattr(args, 'max_retries', 1)
    }
    
    # Create orchestrator
    orchestrator = ParallelOrchestrator(config)
    
    # Determine max workers
    max_workers = None
    if hasattr(args, 'num_gpus') and args.num_gpus:
        max_workers = min(args.num_gpus, len(available_gpus))
    
    # Progress callback
    def progress_callback(message: str):
        console.print(f"[cyan]:gear: {message}[/cyan]")
    
    try:
        # Run parallel execution
        all_results = orchestrator.run_parallel_phase2(
            coders_to_run=coders_to_run,
            all_plans=all_plans,
            strategies_to_run=strategies_to_run,
            max_workers=max_workers,
            progress_callback=progress_callback
        )
        
        # Display execution summary
        metadata = orchestrator.get_execution_metadata()
        console.print(f"\n[bold green]:chart_with_upwards_trend: Parallel Execution Summary[/bold green]")
        console.print(f"  Models processed: {metadata['successful_models']}/{metadata['total_models']}")
        console.print(f"  Total tasks: {metadata['total_tasks']}")
        console.print(f"  Wall clock time: {metadata.get('total_wall_clock_time', 'N/A'):.2f}s")
        console.print(f"  GPU assignments: {metadata['gpu_assignments']}")
        
        if metadata['errors']:
            console.print(f"[bold yellow]:warning: Errors encountered:[/bold yellow]")
            for model, error in metadata['errors'].items():
                console.print(f"    {model}: {error}")
        
        return all_results
        
    except Exception as e:
        logger.error(f"Parallel execution failed: {e}")
        console.print(f"[bold red]:x: Parallel execution failed: {e}[/bold red]")
        console.print("[bold yellow]:turtle: Falling back to sequential execution...[/bold yellow]")
        
        # Fallback to sequential execution
        return _run_sequential_generation(coders_to_run, all_plans, strategies_to_run, args)
    
    finally:
        orchestrator.cleanup()

def _run_sequential_generation(
    coders_to_run: List[str], 
    all_plans: List[Dict[str, Any]], 
    strategies_to_run: List[str],
    args
) -> List[Dict[str, Any]]:
    """
    Run generation phase using sequential execution (original implementation).
    
    This is the fallback method that maintains the original sequential behavior.
    
    Args:
        coders_to_run: List of model names to execute
        all_plans: List of plan dictionaries
        strategies_to_run: List of strategy names
        args: Arguments namespace
    
    Returns:
        List of all results from sequential execution
    """
    from main_orchestrator import initialize_llm, create_instruction_text
    import signal
    
    all_results = []
    
    # Calculate total tasks for progress tracking
    total_tasks = len(coders_to_run) * len(all_plans) * len(strategies_to_run)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} Tasks"),
        TimeElapsedColumn(),
        console=console, 
        transient=False
    ) as progress:
        
        main_task = progress.add_task("[cyan]Generating all code snippets...", total=total_tasks)
        
        for model_name in coders_to_run:
            if model_name not in CODER_MODELS:
                logger.warning(f"Model {model_name} not found in CODER_MODELS, skipping")
                progress.update(main_task, advance=len(all_plans) * len(strategies_to_run))
                continue
            
            # Aggressive memory cleanup before each model
            try:
                from memory_manager import MemoryManager
                memory_manager = MemoryManager()
                memory_manager.cleanup_memory()
                
                memory_info = memory_manager.get_system_memory_info()
                estimated_usage = memory_manager.estimate_model_memory_usage(model_name)
                
                logger.info(f"Loading {model_name}: estimated {estimated_usage:.1f}GB, "
                           f"available {memory_info['available_gb']:.1f}GB ({memory_info['percent']:.1f}% used)")
                
            except Exception as e:
                logger.warning(f"Memory management failed for {model_name}: {e}")
            
            model_info = CODER_MODELS[model_name]
            model_path = model_info['path']
            model_format = model_info['format']
            model_type = "finetuned" if "finetuned" in model_name.lower() else "base"

            console.print(Rule(f":flipper: Processing Coder Model: [bold cyan]{model_name}[/bold cyan] (Format: {model_format})"))

            try:
                coder_llm = initialize_llm(model_path, progress=progress, task_id=main_task)
                if not coder_llm:
                    progress.update(main_task, advance=len(all_plans) * len(strategies_to_run))
                    continue

                for plan_data in all_plans:
                    # Convert strategy names to enum objects
                    strategy_objects = []
                    for strategy_name in strategies_to_run:
                        try:
                            strategy_objects.append(PromptingStrategy[strategy_name])
                        except KeyError:
                            logger.warning(f"Unknown strategy: {strategy_name}, skipping")
                            continue
                    
                    for strategy in strategy_objects:
                        progress.update(main_task, description=f"[cyan] :hamster_face: Model: {model_name} | File: {plan_data['file_name']} | Strategy: {strategy.name}")
                        
                        try:
                            # Create instruction text
                            instruction_prompt = create_instruction_text(
                                strategy=strategy,
                                original_code=plan_data['original_code'],
                                intended_vuln_details=plan_data['intended_vuln'],
                                rag_context=plan_data['rag_context']
                            )

                            # Create final prompt based on model type and format
                            from parallel_execution import _create_final_prompt
                            final_prompt = _create_final_prompt(
                                instruction_prompt, 
                                plan_data['original_code'], 
                                model_type, 
                                model_format
                            )

                            # Set timeout and call LLM
                            signal.alarm(LOCAL_LLM_SIGNAL_TIMEOUT)
                            stop_tokens = ["\n```", "</s>", "[/INST]", "</code>", "<|eot_id|>", "<|im_end|>"]
                            
                            # Truncate prompt to fit context window
                            max_response_tokens = 1024
                            truncated_prompt = truncate_prompt_to_context_window(final_prompt, coder_llm, max_response_tokens, model_path)
                            
                            result = coder_llm(
                                prompt=truncated_prompt,
                                max_tokens=max_response_tokens,
                                stop=stop_tokens,
                                echo=False,
                                temperature=0.1
                            )
                            signal.alarm(0)

                            # Extract generated code
                            choices = result.get('choices', [])
                            generated_code = choices[0].get('text', '').lstrip() if choices and isinstance(choices[0], dict) else ''

                            # Store result
                            all_results.append({
                                "model_full_name": model_name,
                                "file_name": plan_data["file_name"],
                                "original_code": plan_data["original_code"],
                                "intended_vuln": plan_data["intended_vuln"],
                                "rag_context": plan_data.get("rag_context", ""),
                                "prompt_strategy": strategy.name,
                                "final_prompt": final_prompt,
                                "generated_code": generated_code,
                                "static_report": {},
                                "static_confirmation_status": "pending",
                                "static_interpreter_justification": "pending"
                            })

                        except Exception as e:
                            logger.error(f"Error processing {plan_data['file_name']} with {strategy.name}: {e}")
                            # Add failed result for consistency
                            all_results.append({
                                "model_full_name": model_name,
                                "file_name": plan_data["file_name"],
                                "original_code": plan_data["original_code"],
                                "intended_vuln": plan_data["intended_vuln"],
                                "rag_context": plan_data.get("rag_context", ""),
                                "prompt_strategy": strategy.name,
                                "final_prompt": "",
                                "generated_code": "",
                                "static_report": {"error": str(e)},
                                "static_confirmation_status": "FAILURE (Generation Error)",
                                "static_interpreter_justification": f"Generation failed: {e}"
                            })
                        finally:
                            signal.alarm(0)

                        progress.update(main_task, advance=1)
                        
            except Exception as e:
                logger.error(f":x: Crashed during model loading for {model_name}: {e}", exc_info=True)
                progress.update(main_task, advance=len(all_plans) * len(strategies_to_run))
                continue
            finally:
                # Aggressive cleanup after each model
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
                    
                    # Log memory status after cleanup
                    try:
                        from memory_manager import MemoryManager
                        memory_manager = MemoryManager()
                        memory_info = memory_manager.get_system_memory_info()
                        logger.info(f"After {model_name} cleanup: {memory_info['used_gb']:.1f}GB used, "
                                   f"{memory_info['available_gb']:.1f}GB available ({memory_info['percent']:.1f}%)")
                    except Exception:
                        pass
                        
                except Exception as cleanup_error:
                    logger.warning(f"Error during cleanup for {model_name}: {cleanup_error}")
    
    return all_results

def _run_static_analysis_phase(all_results: List[Dict[str, Any]], analyzed_results_path: str, progress_columns) -> None:
    """
    Run the static analysis phase on generated results.
    
    Args:
        all_results: List of results from generation phase
        analyzed_results_path: Path to save analyzed results
        progress_columns: Progress bar column configuration
    """
    static_analysis_agent = StaticAnalysisAgent()
    
    def analyze_record(record):
        try:
            # Run static analysis
            record['static_report'] = static_analysis_agent.run_static_analysis(record['generated_code'])
            # Status remains 'pending' for the next stage
        except Exception as e:
            # If analysis fails, set a specific status
            error_message = f"Code validation failed: {e}"
            record['static_confirmation_status'] = "FAILURE (Syntax Error)"
            record['static_interpreter_justification'] = error_message
            record['semantic_confirmation_status'] = "FAILURE (Syntax Error)"
            record['semantic_justification'] = error_message
            record['static_report'] = {"error": error_message}
        return record

    with ThreadPoolExecutor() as executor:
        with Progress(*progress_columns, console=console, transient=False) as progress:
            task = progress.add_task(f"[cyan] :beer: Analyzing {len(all_results)} snippets...", total=len(all_results))
            futures = [executor.submit(analyze_record, record) for record in all_results]
            for i, future in enumerate(futures):
                all_results[i] = future.result()
                progress.update(task, advance=1)
    
    del static_analysis_agent

    console.print(f"Saving {len(all_results)} analyzed snippets to [cyan]{analyzed_results_path}[/cyan]")
    with open(analyzed_results_path, "wb") as f:
        pickle.dump(all_results, f)
    console.print("✅ Analysis complete and progress saved.")

# Backward compatibility: provide the original function name
run_phase2_execute_coders = run_phase2_execute_coders_parallel