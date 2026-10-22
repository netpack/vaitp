#!/usr/bin/env python3
"""
VAITP Ablation Study Runner

Runs the Phase 3 framework with individual components disabled to measure
their contribution to overall exploitation success. Required by ISSRE reviewers.

Ablation conditions:
  1. full         — Complete system (baseline for comparison)
  2. no_selfcorr  — max_iterations=1 (no self-correction loop)
  3. no_fuzzer    — Fuzzer agent disabled (replan-only recovery)
  4. no_diagnostic — LLM exploit failure analysis disabled (mechanical recovery)
  5. no_rag       — No proven plans as few-shot examples
  6. no_hooks     — Side-effect hooks disabled (only natural exploits possible)
  7. oneshot      — Plain one-shot LLM baseline (no SEP/CEP/AEP/FEP decomposition)

Usage:
    python scripts/run_ablation_study.py --vertex-config configs/config_gemini.yaml --condition full
    python scripts/run_ablation_study.py --vertex-config configs/config_gemini.yaml --condition no_fuzzer
    python scripts/run_ablation_study.py --vertex-config configs/config_gemini.yaml --condition all
    python scripts/run_ablation_study.py --ollama --model deepseek-r1:14b --condition no_selfcorr

Results are saved to: ablation_results/<condition>_<model>_<timestamp>.json
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch as mock_patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structures import SEP, CEP, AEP, FEP, VerificationReport, TestVerdict
from orchestration.phase3_orchestrator import Phase3Orchestrator
from orchestration.planner_agent import PlannerAgent
from orchestration.fuzzer_agent import FuzzerAgent
from plan_saver import load_proven_plans

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATASET_DIR = "vaitp_dataset/phase3_genuine"
OUTPUT_DIR = "ablation_results"
CONDITIONS = ["full", "no_selfcorr", "no_fuzzer", "no_diagnostic", "no_rag", "no_hooks", "oneshot"]


def get_test_files(dataset_dir=None):
    """Get all test files (vuln/patch pairs) from the dataset."""
    base = dataset_dir or DATASET_DIR
    vuln_dir = os.path.join(base, "vulnerable")
    patch_dir = os.path.join(base, "injectable")
    
    test_files = []
    for fname in sorted(os.listdir(vuln_dir)):
        if not fname.endswith(".py"):
            continue
        vuln_path = os.path.join(vuln_dir, fname)
        patch_path = os.path.join(patch_dir, fname)
        if os.path.exists(patch_path):
            test_files.append((fname, vuln_path, patch_path))
    return test_files


def create_llm_fn(args):
    """Create the LLM generation function based on CLI arguments."""
    if args.vertex_config:
        from vertex_backend import create_vertex_fn, load_vertex_config
        vcfg = load_vertex_config(args.vertex_config)
        logger.info(f"  Vertex AI model: {vcfg['model']}")
        llm_fn = create_vertex_fn(model=vcfg['model'], api_base=vcfg['api_base'])
        model_name = vcfg['model']
    elif args.ollama:
        from run_phase3 import create_ollama_fn
        llm_fn = create_ollama_fn(args.model)
        model_name = args.model
    else:
        logger.error("Must specify either --vertex-config or --ollama")
        sys.exit(1)
    return llm_fn, model_name


def run_condition(condition: str, llm_fn, model_name: str, test_files: list, 
                  max_files: int = 100, test_timeout: int = 120, symmetric_hooks: bool = False,
                  jury=None):
    """Run a single ablation condition across all test files.

    When ``jury`` is provided, the planner/fuzzer use jury-tagged decision
    functions (allowlisted decisions go to the panel + judge); everything else
    behaves identically to the single-model path.
    """
    # Derive decision-tagged functions when a jury is active. The planner fn is
    # UNTAGGED: PlannerAgent tags each call site (phase3.plan.infrastructure/
    # payloads/edit) and the orchestrator tags phase3.recovery. Only allowlisted
    # tags vote; every other call runs on the primary juror alone.
    planner_fn = jury.make_fn() if jury is not None else llm_fn
    fuzzer_fn = jury.make_fn("phase3.fuzz") if jury is not None else llm_fn
    base_fn = jury.make_fn() if jury is not None else llm_fn
    
    logger.info(f"\n{'='*70}")
    logger.info(f"  ABLATION: {condition} | Model: {model_name}")
    logger.info(f"{'='*70}\n")
    
    results = {
        "condition": condition,
        "model": model_name,
        "timestamp": datetime.now().isoformat(),
        "total": 0,
        "passed": 0,
        "failed": 0,
        "tests": {},
    }
    
    # Load proven plans (disabled for no_rag condition)
    proven_plans = None
    if condition != "no_rag":
        proven_plans = load_proven_plans()
    
    # Determine max iterations
    max_iterations = 5  # Default (same as main evaluation)
    if condition == "no_selfcorr":
        max_iterations = 1
    
    # Create planner (always needed unless oneshot)
    if condition == "oneshot":
        return run_oneshot_baseline(base_fn, model_name, test_files, max_files,
                                    test_timeout, symmetric_hooks)
    
    planner = PlannerAgent(llm_generate_fn=planner_fn)
    
    # Create fuzzer (disabled for no_fuzzer condition)
    fuzzer = None
    if condition != "no_fuzzer":
        fuzzer = FuzzerAgent(llm_generate_fn=fuzzer_fn, max_mutations=5)
    
    orchestrator = Phase3Orchestrator(
        planner=planner,
        fuzzer=fuzzer,
        model_name=model_name,
        experiment_name=f"ablation_{condition}",
        test_timeout=test_timeout,
        symmetric_hooks=symmetric_hooks,
    )

    # Crash-resilient checkpoint: results are saved after every test and reloaded
    # on resume, so an unexpected crash never loses completed work.
    _model_short = model_name.split("/")[-1].replace("-", "_").replace(".", "_")
    checkpoint = os.path.join(OUTPUT_DIR, f"checkpoint_{condition}_{_model_short}.json")
    done = set()
    if os.path.exists(checkpoint):
        try:
            prev = json.load(open(checkpoint))
            results["tests"] = prev.get("tests", {})
            done = set(results["tests"].keys())
            results["passed"] = sum(1 for t in results["tests"].values() if t.get("passed"))
            results["failed"] = len(results["tests"]) - results["passed"]
            results["total"] = len(results["tests"])
            logger.info(f"  [Resume] Loaded checkpoint with {len(done)} completed tests")
        except Exception as e:
            logger.warning(f"  [Resume] Could not load checkpoint ({e}); starting fresh")

    def _save_checkpoint():
        results["rate"] = (results["passed"] / results["total"] * 100) if results["total"] else 0
        try:
            with open(checkpoint, "w") as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            logger.warning(f"  [Checkpoint] save failed: {e}")

    try:
        for i, (fname, vuln_path, patch_path) in enumerate(test_files[:max_files]):
            test_name = fname.replace(".py", "")
            if test_name in done:
                continue
            logger.info(f"\n  [{i+1}/{min(max_files, len(test_files))}] {test_name}")

            with open(vuln_path) as f:
                vuln_code = f.read()
            with open(patch_path) as f:
                patch_code = f.read()

            # Extract CWE from filename
            cwe = fname.split("_")[0].upper().replace("CWE", "CWE-")
            vuln_description = f"Vulnerability type: {cwe}"

            report = None
            err = None
            # Apply condition-specific modifications
            original_analyze = orchestrator._llm_analyze_exploit_failure
            original_decide = orchestrator._llm_decide_recovery

            if condition == "no_diagnostic":
                # Disable LLM exploit failure analysis — use mechanical recovery only
                orchestrator._llm_analyze_exploit_failure = lambda *a, **kw: None
                orchestrator._llm_decide_recovery = lambda report, *a, **kw: Phase3Orchestrator._mechanical_recovery(report)

            try:
                if condition == "no_hooks":
                    # Disable side-effect hooks and auto-injector
                    orchestrator._llm_generate_side_effect_hook = lambda *a, **kw: None
                    with mock_patch('orchestration.phase3_orchestrator.inject_side_effect',
                                  side_effect=lambda code, *a, **kw: code):
                        report = orchestrator.run_with_planner(
                            test_name=test_name,
                            vuln_code=vuln_code,
                            patch_code=patch_code,
                            vuln_description=vuln_description,
                            vuln_path=vuln_path,
                            patch_path=patch_path,
                            max_iterations=max_iterations,
                            proven_plans=proven_plans,
                        )
                else:
                    report = orchestrator.run_with_planner(
                        test_name=test_name,
                        vuln_code=vuln_code,
                        patch_code=patch_code,
                        vuln_description=vuln_description,
                        vuln_path=vuln_path,
                        patch_path=patch_path,
                        max_iterations=max_iterations,
                        proven_plans=proven_plans,
                    )
            except Exception as e:
                # One test's failure must never abort the whole run. Record it as
                # an errored (failed) test and continue with the rest.
                import traceback as _tb
                err = "%s: %s" % (type(e).__name__, e)
                logger.error(f"    [Error] test '{test_name}' raised: {err}")
                logger.debug(_tb.format_exc())
            finally:
                # Restore originals for next test
                if condition == "no_diagnostic":
                    orchestrator._llm_analyze_exploit_failure = original_analyze
                    orchestrator._llm_decide_recovery = original_decide

            passed = bool(report.passed) if report else False
            results["total"] += 1
            if passed:
                results["passed"] += 1
            else:
                results["failed"] += 1

            if err is not None:
                results["tests"][test_name] = {
                    "passed": False, "iteration": 0,
                    "failure_reasons": ["Exception: " + err],
                }
                logger.info(f"    ERROR ({err[:60]})")
            else:
                results["tests"][test_name] = {
                    "passed": passed,
                    "iteration": report.iteration if report else 0,
                    "failure_reasons": report.failure_reasons if report and not passed else [],
                }
                logger.info(f"    {'PASS' if passed else 'FAIL'} "
                           f"(iteration {report.iteration if report else 0})")

            _save_checkpoint()

    finally:
        orchestrator.shutdown()

    results["rate"] = (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0
    return results


def run_oneshot_baseline(llm_fn, model_name: str, test_files: list, 
                         max_files: int = 100, test_timeout: int = 120,
                         symmetric_hooks: bool = False):
    """
    One-shot LLM baseline: No structured plan decomposition.
    
    Instead of SEP/CEP/AEP/FEP, we ask the LLM to directly generate
    a complete exploit payload that creates /tmp/pwned when the vulnerability
    is triggered. This measures the value of structured planning.
    """
    results = {
        "condition": "oneshot",
        "model": model_name,
        "timestamp": datetime.now().isoformat(),
        "total": 0,
        "passed": 0,
        "failed": 0,
        "tests": {},
    }
    
    ONESHOT_PROMPT = """You are a security researcher. Given vulnerable Python code, generate a SINGLE exploit payload that proves the vulnerability is exploitable by creating the file /tmp/pwned.

VULNERABLE CODE:
```python
{vuln_code}
```

The program reads from stdin (for CLI) or accepts HTTP requests (for Flask apps).

Respond with ONLY the raw payload string to send as input. No explanation, no code blocks, just the payload.
If it's a Flask app, respond with: METHOD URL BODY (e.g., "GET /test?q=payload" or "POST /action data=payload")
"""
    
    # Create the orchestrator ONCE with the per-test timeout so hanging
    # Docker/curl calls are force-killed instead of blocking indefinitely.
    orch = Phase3Orchestrator(
        model_name=model_name,
        experiment_name="ablation_oneshot",
        test_timeout=test_timeout,
        symmetric_hooks=symmetric_hooks,
    )
    
    try:
        for i, (fname, vuln_path, patch_path) in enumerate(test_files[:max_files]):
            test_name = fname.replace(".py", "")
            logger.info(f"\n  [{i+1}/{min(max_files, len(test_files))}] {test_name} (oneshot)")
            
            with open(vuln_path) as f:
                vuln_code = f.read()
            
            try:
                # Generate payload with one-shot prompt
                prompt = ONESHOT_PROMPT.format(vuln_code=vuln_code[:3000])
                payload = llm_fn(prompt, max_tokens=512)
                
                # Execute in Docker with minimal setup
                sep = SEP(
                    target_id=test_name,
                    image="python:3.9-slim",
                    working_dir="/app",
                    dependencies=["pip:flask", "curl", "procps"],
                )
                cep = CEP(success_file="/tmp/pwned", strategy="stdio")
                aep = AEP(tries=[{"input": payload.strip(), "response": None}])
                fep = FEP(tries=[{"input": "test", "response": ""}])
                
                report = orch.run_single_test(
                    test_name, sep, cep, aep, fep, vuln_path, patch_path
                )
                
                passed = report.passed if report else False
            except Exception as e:
                logger.warning(f"    Error: {e}")
                passed = False
            
            results["total"] += 1
            if passed:
                results["passed"] += 1
            else:
                results["failed"] += 1
            results["tests"][test_name] = {"passed": passed}
            logger.info(f"    {'PASS' if passed else 'FAIL'}")
    finally:
        orch.shutdown()
    
    results["rate"] = (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0
    return results


def main():
    parser = argparse.ArgumentParser(description="VAITP Ablation Study")
    parser.add_argument("--condition", choices=CONDITIONS + ["all"], default="all",
                       help="Ablation condition to run")
    parser.add_argument("--vertex-config", type=str, default=None,
                       help="Path to Vertex AI YAML config (e.g. configs/config_gemini.yaml)")
    parser.add_argument("--ollama", action="store_true",
                       help="Use Ollama backend")
    parser.add_argument("--model", default="deepseek-r1:14b",
                       help="Model name (for Ollama backend)")
    parser.add_argument("--voting-config", type=str, default=None,
                       help="Path to a YAML config with a 'voting:' block. When set, "
                            "allowlisted decisions are decided by a jury of models + a "
                            "judge (ablation dimension: single model vs jury).")
    parser.add_argument("--max-files", type=int, default=100,
                       help="Maximum number of test files to process")
    parser.add_argument("--test-timeout", type=int, default=120,
                       help="Per-test timeout in seconds to prevent hangs (default: 120)")
    parser.add_argument("--symmetric-hooks", action="store_true",
                       help="Apply the same sink-level detector to the patched code too "
                            "(symmetric differential Condition 4 for hook-assisted types)")
    parser.add_argument("--dataset-dir", default=DATASET_DIR,
                       help="Dataset root containing vulnerable/ and injectable/ "
                            "(default: %s)" % DATASET_DIR)
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                       help="Output directory for results")
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)

    # Pre-flight: Docker must be running (containers are required for verification).
    try:
        from docker_utils import check_docker_available
        if not check_docker_available():
            logger.error("Docker daemon is not reachable. Start Docker Desktop "
                         "(or `colima start`) and re-run. No tests were executed.")
            sys.exit(2)
    except Exception as e:
        logger.error(f"Could not verify Docker availability ({e}). "
                     "Ensure Docker is running and re-run.")
        sys.exit(2)

    # Create LLM function
    llm_fn, model_name = create_llm_fn(args)

    # Optional jury (multi-model voting) as an ablation dimension.
    jury = None
    if getattr(args, "voting_config", None):
        from orchestration.voting_jury import load_voting_config, build_jury
        vote_cfg = load_voting_config(args.voting_config)
        jury = build_jury(vote_cfg, tracer=None)
        if jury is not None:
            model_name = vote_cfg.label()
            logger.info(f"Jury enabled: jurors={jury.juror_ids}, "
                        f"decisions={list(vote_cfg.decisions.keys())}")
        else:
            logger.warning("--voting-config provided but voting is disabled/empty; "
                           "using single model.")

    test_files = get_test_files(args.dataset_dir)
    logger.info(f"Found {len(test_files)} test files in {args.dataset_dir}")
    
    conditions = CONDITIONS if args.condition == "all" else [args.condition]
    
    all_results = {}
    for condition in conditions:
        results = run_condition(condition, llm_fn, model_name, test_files, 
                               args.max_files, args.test_timeout, args.symmetric_hooks,
                               jury=jury)
        all_results[condition] = results
        
        # Save individual condition results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_short = model_name.split("/")[-1].replace("-", "_")
        outfile = os.path.join(
            args.output_dir,
            f"{condition}_{model_short}_{timestamp}.json"
        )
        with open(outfile, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"  Saved: {outfile}")
    
    # Print summary
    print("\n" + "="*70)
    print("  ABLATION STUDY SUMMARY")
    print("="*70)
    print(f"{'Condition':<16} {'Passed':<8} {'Total':<8} {'Rate':<8}")
    print("-"*40)
    for cond, res in all_results.items():
        print(f"{cond:<16} {res['passed']:<8} {res['total']:<8} {res['rate']:.1f}%")
    print("="*70)
    
    # Save combined summary
    summary_file = os.path.join(args.output_dir, f"summary_{model_short}_{timestamp}.json")
    with open(summary_file, "w") as f:
        json.dump(all_results, f, indent=2)
    logger.info(f"Summary saved: {summary_file}")


if __name__ == "__main__":
    main()
