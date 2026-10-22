#!/usr/bin/env python3
"""
VAITP Phase A: Mutation Testing Runner
Runs the 30 mutation variants through the Phase 3 orchestrator.
Since mutations preserve the same vulnerability logic, the Agent
should succeed 100%. This calibrates the system.

Usage:
    # 1. Generate the mutation files first:
    python gold_standard/generate_mutations.py

    # 2. Run mutation tests:
    python test_phase3_mutations.py                # All mutations
    python test_phase3_mutations.py --category yaml  # Only YAML mutations
    python test_phase3_mutations.py yaml_v2.py     # Single test
"""
import sys
import os
import logging

from gold_standard.mutation_registry import get_mutation_registry
from orchestration.phase3_orchestrator import Phase3Orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# Category filters for convenience
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


def main():
    args = sys.argv[1:]
    registry = get_mutation_registry()

    # Filter
    if args and args[0].startswith("--category"):
        if "=" in args[0]:
            cat = args[0].split("=")[1]
        elif len(args) > 1:
            cat = args[1]
        else:
            print(f"Available categories: {list(CATEGORIES.keys())}")
            sys.exit(0)
        if cat not in CATEGORIES:
            print(f"Unknown category '{cat}'. Available: {list(CATEGORIES.keys())}")
            sys.exit(1)
        filenames = CATEGORIES[cat]
        registry = {k: v for k, v in registry.items() if k in filenames}
    elif args:
        registry = {k: v for k, v in registry.items() if k in args}
        if not registry:
            print(f"No matching tests. Available: {list(get_mutation_registry().keys())}")
            sys.exit(1)

    orchestrator = Phase3Orchestrator()
    results = orchestrator.run_regression_suite(registry)

    all_passed = all(r.passed for r in results)
    passed = sum(1 for r in results if r.passed)
    print(f"\nMutation Score: {passed}/{len(results)}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
