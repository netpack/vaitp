#!/usr/bin/env python3
"""
VAITP Phase 3: Diagnostic Agent Runner
Runs the automated debugging loop using a local LLM (llama-cpp-python)
to diagnose and fix failing mutation tests.

The agent replicates the manual critical thinking process:
  - Observes test failures (Truth Table violations)
  - Reads vulnerable/patched code to understand context
  - Uses LLM to analyze root cause and propose AEP/SEP fixes
  - Applies fixes and re-runs tests
  - Iterates until all pass or max attempts exhausted

Usage:
    # Run diagnostic on all mutations (uses deepthink-7b by default):
    python test_phase3_diagnostic.py

    # Use a specific model:
    python test_phase3_diagnostic.py --model llama-3.1-8b

    # Run on a specific category:
    python test_phase3_diagnostic.py --category yaml

    # Run on a single test:
    python test_phase3_diagnostic.py --test eval_v2.py

    # Dry run (test with MockLLM, no GPU needed):
    python test_phase3_diagnostic.py --mock

    # Set max fix attempts per test:
    python test_phase3_diagnostic.py --max-attempts 5

    # Export fix report to JSON:
    python test_phase3_diagnostic.py --export diagnostic_report.json
"""
import sys
import os
import json
import argparse
import logging
import time

from gold_standard.mutation_registry import get_mutation_registry
from orchestration.diagnostic_agent import DiagnosticAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Category filters (same as test_phase3_mutations.py)
CATEGORIES = {
    "subprocess": ["1167_v2.py", "1167_v3.py", "1167_v4.py"],
    "yaml": ["yaml_v2.py", "yaml_v3.py", "yaml_v4.py"],
    "sqli": ["sqli_v2.py", "sqli_v3.py", "sqli_v4.py"],
    "eval": ["eval_v2.py", "eval_v3.py", "eval_v4.py"],
    "ssti": ["ssti_v2.py", "ssti_v3.py", "ssti_v4.py"],
    "pickle": ["pickle_v2.py", "pickle_v3.py", "pickle_v4.py"],
    "mako": ["mako_v2.py", "mako_v3.py", "mako_v4.py"],
    "xslt": ["xslt_v2.py", "xslt_v3.py", "xslt_v4.py"],
    "zip": ["zip_v2.py", "zip_v3.py", "zip_v4.py"],
    "git": ["360_v2.py", "360_v3.py", "360_v4.py"],
    "flask_rce": ["flask_v2.py", "flask_v3.py", "flask_v4.py"],
    "flask_ssti": ["flask_ssti_v2.py", "flask_ssti_v3.py", "flask_ssti_v4.py"],
    "flask_json": ["flask_json_v2.py", "flask_json_v3.py", "flask_json_v4.py"],
    "flask_upload": ["flask_upload_v2.py", "flask_upload_v3.py", "flask_upload_v4.py"],
    "flask_header": ["flask_header_v2.py", "flask_header_v3.py", "flask_header_v4.py"],
    "flask_pickle": ["flask_pickle_v2.py", "flask_pickle_v3.py", "flask_pickle_v4.py"],
    "flask_ssrf": ["flask_ssrf_v2.py", "flask_ssrf_v3.py", "flask_ssrf_v4.py"],
    "flask_jwt": ["flask_jwt_v2.py", "flask_jwt_v3.py", "flask_jwt_v4.py"],
    "flask_nosql": ["flask_nosql_v2.py", "flask_nosql_v3.py", "flask_nosql_v4.py"],
    "flask_nosql_real": ["flask_nosql_real_v2.py", "flask_nosql_real_v3.py", "flask_nosql_real_v4.py"],
}


# ==========================================
# LOCAL LLM LOADER
# ==========================================
def create_llm_generate_fn(model_key: str = "deepthink-7b", n_ctx_override: int = None):
    """
    Create an llm_generate_fn callable using llama-cpp-python.
    Loads the model once and returns a closure.

    Args:
        model_key: Key from REASONING_MODELS or CODER_MODELS in config.py.
        n_ctx_override: If set, overrides the context window size. Useful for
                        large models on memory-constrained systems where the
                        default 32K KV cache won't fit alongside the model weights.
    """
    from config import REASONING_MODELS, LLM_N_GPU_LAYERS, LLM_N_THREADS, LLM_USE_MMAP

    if model_key not in REASONING_MODELS:
        # Try coder models
        from config import CODER_MODELS
        if model_key not in CODER_MODELS:
            available = list(REASONING_MODELS.keys())
            print(f"Unknown model '{model_key}'. Available: {available}")
            sys.exit(1)
        model_info = CODER_MODELS[model_key]
    else:
        model_info = REASONING_MODELS[model_key]

    model_path = model_info["path"]
    if not os.path.exists(model_path):
        print(f"Model file not found: {model_path}")
        sys.exit(1)

    if n_ctx_override:
        n_ctx = n_ctx_override
    else:
        n_ctx = model_info.get("context_window", 8192)

    logger.info(f"Loading model: {model_key} ({model_path})")
    logger.info(f"  Context: {n_ctx}, GPU layers: {LLM_N_GPU_LAYERS}, Threads: {LLM_N_THREADS}")

    from llama_cpp import Llama

    t0 = time.time()
    llm = Llama(
        model_path=model_path,
        n_ctx=n_ctx,
        n_gpu_layers=LLM_N_GPU_LAYERS,
        n_threads=LLM_N_THREADS,
        use_mmap=LLM_USE_MMAP,
        verbose=False,
    )
    elapsed = time.time() - t0
    logger.info(f"  Model loaded in {elapsed:.1f}s")

    def generate(prompt: str, max_tokens: int = 1024) -> str:
        response = llm(
            prompt,
            max_tokens=max_tokens,
            temperature=0.3,
            top_p=0.9,
            stop=["```\n\n", "\n\n\n"],
        )
        if isinstance(response, dict) and "choices" in response:
            return response["choices"][0].get("text", "")
        return str(response)

    return generate


# ==========================================
# MOCK LLM (for testing without GPU)
# ==========================================
class MockDiagnosticLLM:
    """
    Simulates an LLM that can diagnose common failure patterns.
    Uses heuristic pattern matching on the prompt to return plausible fixes.
    Useful for testing the diagnostic pipeline without loading a real model.
    """

    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        self.call_count += 1

        # Parse failure type from prompt
        if "Vuln Broken" in prompt or "Patch Broken" in prompt:
            # Benign input issue — try to fix FEP tries
            return json.dumps({
                "root_cause": "FEP tries response doesn't match actual output",
                "fix_type": "aep_field",
                "fixes": [
                    {"target": "fep", "field": "tries", "new_value": [{"input": "test", "response": "output"}]}
                ]
            })

        if "Vuln Safe" in prompt:
            return json.dumps({
                "root_cause": "Payload doesn't trigger the vulnerability in this code variant",
                "fix_type": "code_change",
                "fixes": [],
                "note": "Requires manual review of the vulnerable code to ensure exploitability"
            })

        if "Patch Bypassed" in prompt:
            return json.dumps({
                "root_cause": "Patch does not effectively block the exploit",
                "fix_type": "code_change",
                "fixes": [],
                "note": "Patched code needs to be rewritten to properly sanitize input"
            })

        # Default: generic response
        return json.dumps({
            "root_cause": "Unable to determine specific root cause",
            "fix_type": "aep_field",
            "fixes": []
        })


# ==========================================
# MAIN
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="VAITP Diagnostic Agent — Automated debugging with local LLM"
    )
    parser.add_argument(
        "--model", default="deepthink-7b",
        help="Model key from config.py (default: deepthink-7b)"
    )
    parser.add_argument(
        "--category", choices=list(CATEGORIES.keys()),
        help="Run only tests in this category"
    )
    parser.add_argument(
        "--test", help="Run diagnostic on a single test file"
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Use MockLLM instead of real model (for pipeline testing)"
    )
    parser.add_argument(
        "--max-attempts", type=int, default=3,
        help="Max fix attempts per failing test (default: 3)"
    )
    parser.add_argument(
        "--export", help="Export diagnostic report to JSON file"
    )
    parser.add_argument(
        "--list-models", action="store_true",
        help="List available models and exit"
    )
    parser.add_argument(
        "--autonomous", action="store_true",
        help="Autonomous mode: LLM generates SEP/AEP from scratch (no pre-written plans)"
    )
    parser.add_argument(
        "--context", type=int, default=None,
        help="Override model context window size (n_ctx). Use 4096 or 8192 for "
             "large models on memory-constrained systems (default: auto from config, capped at 32768)"
    )
    args = parser.parse_args()

    # List models
    if args.list_models:
        from config import REASONING_MODELS, CODER_MODELS
        print("\nReasoning models:")
        for key, info in REASONING_MODELS.items():
            exists = "✓" if os.path.exists(info["path"]) else "✗"
            print(f"  {exists} {key:<30} {info['path']}")
        print("\nCoder models:")
        for key, info in CODER_MODELS.items():
            exists = "✓" if os.path.exists(info["path"]) else "✗"
            print(f"  {exists} {key:<30} {info['path']}")
        sys.exit(0)

    # Build registry
    registry = get_mutation_registry()

    if args.category:
        filenames = CATEGORIES[args.category]
        registry = {k: v for k, v in registry.items() if k in filenames}
    elif args.test:
        registry = {k: v for k, v in registry.items() if k == args.test}
        if not registry:
            print(f"Test '{args.test}' not found. Available: {list(get_mutation_registry().keys())}")
            sys.exit(1)

    # Create LLM
    if args.mock:
        logger.info("Using MockDiagnosticLLM (no GPU required)")
        mock = MockDiagnosticLLM()
        llm_fn = mock.generate
    else:
        llm_fn = create_llm_generate_fn(args.model, n_ctx_override=args.context)

    # Create and run diagnostic agent
    agent = DiagnosticAgent(
        llm_generate_fn=llm_fn,
        max_fix_attempts=args.max_attempts,
        dataset_dir="vaitp_dataset",
    )

    if args.autonomous:
        # Autonomous mode: LLM generates SEP/AEP from scratch
        filenames = list(registry.keys())
        summary = agent.run_autonomous_suite(filenames)
    else:
        # Standard mode: diagnose and fix pre-written SEP/AEP
        summary = agent.run_diagnostic_suite(registry)

    # Export if requested
    if args.export:
        # Make it JSON-serializable
        export_data = {
            "model": args.model if not args.mock else "mock",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": summary["total_tests"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "total_fix_attempts": summary["total_fix_attempts"],
            "duration_seconds": round(summary["duration_seconds"], 2),
            "results": summary["results"],
        }
        with open(args.export, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        logger.info(f"Report exported to {args.export}")

    # Exit code
    sys.exit(0 if summary["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
