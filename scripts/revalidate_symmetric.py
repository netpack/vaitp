#!/usr/bin/env python3
"""
Symmetric-Instrumentation Re-validation (ISSRE Experiment 1)

Deterministically re-runs previously-SUCCESSFUL exploitation plans under the
stronger symmetric double-check: the SAME sink-level detector applied to the
vulnerable code is also applied to the patched code. This turns Condition 4
("safe code blocks the exploit") into a true differential test for hook-assisted
vulnerability types.

Question answered: of the exploitation successes, how many remain PASS when the
patched version is held to the same instrumented detector? Survivors are robust;
flips to FAIL reveal cases where the previous PASS depended on the patched code
simply lacking the detector (i.e., incomplete patches, e.g. the wget case).

Because it replays SAVED plans (no LLM re-planning), this run is deterministic and
cheap: it only processes tests that already passed, with no model API calls.

Usage:
    # Re-validate Gemini's successful plans (both baseline + symmetric for comparison)
    python scripts/revalidate_symmetric.py \
        --plans-dir "backups/run_gemini_complete/generated_plans/exploited" \
        --model-label "Gemini 3.1 Pro"

    # Symmetric only (faster), against a different model's exploited plans
    python scripts/revalidate_symmetric.py \
        --plans-dir "backups/run_grok_complete/generated_plans/exploited" \
        --mode symmetric

Requires Docker (same as the main pipeline). No Vertex/LLM configuration needed.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime

# Project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structures import SEP, CEP, AEP, FEP, TestVerdict
from orchestration.phase3_orchestrator import Phase3Orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATASET_DIR = "vaitp_dataset/phase3_sven_pyvul"
OUTPUT_DIR = "ablation_results"

# CWE types whose exploit is a NATURAL file-creation (payload creates the file
# directly). For these, the patch check is already a true differential test and
# symmetric instrumentation is a no-op. The rest are HOOK-ASSISTED.
NATURAL_CWES = {"cwe78", "cwe94", "cwe22", "cwe502"}


def extract_cwe(test_name: str) -> str:
    parts = test_name.lower().replace(".py", "").split("_")
    return parts[0] if parts and parts[0].startswith("cwe") else "unknown"


def evidence_level(test_name: str) -> str:
    return "natural" if extract_cwe(test_name) in NATURAL_CWES else "hook_assisted"


def load_plans(plans_dir: str) -> list:
    """Load saved exploited plans (test_name + SEP/CEP/AEP/FEP) from a directory."""
    plans = []
    if not os.path.isdir(plans_dir):
        logger.error(f"Plans directory not found: {plans_dir}")
        return plans
    for fname in sorted(os.listdir(plans_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(plans_dir, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"  Could not read {fpath}: {e}")
            continue
        # Only re-validate plans that were recorded as passing
        if not data.get("passed", False):
            continue
        test_name = data.get("test_name", fname.replace(".json", ".py"))
        plans.append((test_name, data))
    return plans


def resolve_paths(test_name: str):
    """Map a test name to its vulnerable/patched dataset files."""
    base = test_name if test_name.endswith(".py") else f"{test_name}.py"
    vuln_path = os.path.join(DATASET_DIR, "vulnerable", base)
    patch_path = os.path.join(DATASET_DIR, "injectable", base)
    if os.path.exists(vuln_path) and os.path.exists(patch_path):
        return vuln_path, patch_path
    return None, None


def run_one(orch: Phase3Orchestrator, test_name: str, data: dict):
    """Replay a single saved plan through run_single_test. Returns (passed, reasons)."""
    vuln_path, patch_path = resolve_paths(test_name)
    if not vuln_path:
        logger.warning(f"  [skip] dataset files not found for {test_name}")
        return None, ["dataset files not found"]

    sep = SEP.from_dict(data.get("sep", {}))
    cep = CEP.from_dict(data.get("cep", {}))
    aep = AEP.from_dict(data.get("aep", {}))
    fep = FEP.from_dict(data.get("fep", {}))

    report = orch.run_single_test(test_name, sep, cep, aep, fep, vuln_path, patch_path)
    passed = bool(report.passed) if report else False
    reasons = (report.failure_reasons or []) if report else ["no report"]
    return passed, reasons


def run_mode(plans: list, symmetric: bool, test_timeout: int) -> dict:
    """Run all plans under one instrumentation mode (symmetric on/off)."""
    label = "symmetric" if symmetric else "baseline"
    logger.info(f"\n{'='*70}\n  RE-VALIDATION MODE: {label}\n{'='*70}")
    orch = Phase3Orchestrator(
        model_name=f"revalidate_{label}",
        experiment_name=f"revalidate_{label}",
        test_timeout=test_timeout,
        symmetric_hooks=symmetric,
    )
    out = {"natural": {"pass": 0, "fail": 0}, "hook_assisted": {"pass": 0, "fail": 0},
           "tests": {}}
    try:
        for i, (test_name, data) in enumerate(plans):
            level = evidence_level(test_name)
            logger.info(f"\n  [{i+1}/{len(plans)}] {test_name} ({level}, {label})")
            passed, reasons = run_one(orch, test_name, data)
            if passed is None:
                continue
            bucket = "pass" if passed else "fail"
            out[level][bucket] += 1
            out["tests"][test_name] = {
                "level": level, "passed": passed, "failure_reasons": reasons,
            }
            logger.info(f"    {'PASS' if passed else 'FAIL'}"
                        + ("" if passed else f"  ({'; '.join(reasons)})"))
    finally:
        orch.shutdown()
    return out


def main():
    parser = argparse.ArgumentParser(description="Symmetric-instrumentation re-validation")
    parser.add_argument("--plans-dir",
                        default="backups/run_gemini_complete/generated_plans/exploited",
                        help="Directory of saved exploited plans (test_name + SEP/CEP/AEP/FEP)")
    parser.add_argument("--model-label", default="Gemini 3.1 Pro",
                        help="Human-readable model label for the report")
    parser.add_argument("--mode", choices=["symmetric", "baseline", "both"], default="both",
                        help="Run symmetric only, baseline only, or both for comparison")
    parser.add_argument("--test-timeout", type=int, default=120,
                        help="Per-test timeout in seconds (default: 120)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
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

    plans = load_plans(args.plans_dir)
    if not plans:
        logger.error("No passing plans found to re-validate.")
        sys.exit(1)
    n_nat = sum(1 for t, _ in plans if evidence_level(t) == "natural")
    n_hook = len(plans) - n_nat
    logger.info(f"Loaded {len(plans)} passing plans "
                f"({n_nat} natural, {n_hook} hook-assisted) from {args.plans_dir}")

    results = {
        "model_label": args.model_label,
        "plans_dir": args.plans_dir,
        "timestamp": datetime.now().isoformat(),
        "n_plans": len(plans),
    }

    if args.mode in ("baseline", "both"):
        results["baseline"] = run_mode(plans, symmetric=False, test_timeout=args.test_timeout)
    if args.mode in ("symmetric", "both"):
        results["symmetric"] = run_mode(plans, symmetric=True, test_timeout=args.test_timeout)

    # --- Summary ---
    print("\n" + "=" * 72)
    print(f"  SYMMETRIC RE-VALIDATION SUMMARY — {args.model_label}")
    print("=" * 72)

    def _fmt(mode_key):
        if mode_key not in results:
            return
        m = results[mode_key]
        nat_p, nat_f = m["natural"]["pass"], m["natural"]["fail"]
        hk_p, hk_f = m["hook_assisted"]["pass"], m["hook_assisted"]["fail"]
        total_p = nat_p + hk_p
        total = total_p + nat_f + hk_f
        print(f"\n  [{mode_key}]")
        print(f"    Natural      : {nat_p}/{nat_p + nat_f} pass")
        print(f"    Hook-assisted: {hk_p}/{hk_p + hk_f} pass")
        print(f"    TOTAL        : {total_p}/{total} pass")

    _fmt("baseline")
    _fmt("symmetric")

    # Highlight flips (tests that passed baseline but failed symmetric)
    if "baseline" in results and "symmetric" in results:
        flips = []
        for t, info in results["symmetric"]["tests"].items():
            base = results["baseline"]["tests"].get(t, {})
            if base.get("passed") and not info["passed"]:
                flips.append((t, info["failure_reasons"]))
        print("\n  Flips (PASS baseline -> FAIL symmetric):")
        if flips:
            for t, reasons in flips:
                print(f"    - {t}: {'; '.join(reasons)}")
            print(f"\n  {len(flips)} flip(s). These indicate patches that only 'blocked' "
                  "the exploit\n  because the patched code lacked the detector "
                  "(candidate incomplete patches).")
        else:
            print("    None — all successes are robust under symmetric instrumentation.")
    print("=" * 72)

    # Save
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = args.model_label.replace(" ", "_").replace(".", "_")
    outfile = os.path.join(args.output_dir, f"revalidate_symmetric_{label}_{ts}.json")
    with open(outfile, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved: {outfile}")


if __name__ == "__main__":
    main()
