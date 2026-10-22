#!/usr/bin/env python3
"""
VAITP Phase 3: Planner Self-Correction Loop Test
Proves the feedback loop works by simulating an LLM that:
  1. First attempt: Returns a BROKEN plan (wrong benign_response)
  2. Second attempt: Reads the feedback and returns a FIXED plan

Usage:
    python test_phase3_planner_loop.py              # Run all planner tests
    python test_phase3_planner_loop.py --quick       # Run only 2 fast tests
"""
import sys
import os
import json
import logging

from structures import SEP, CEP, AEP, FEP, PlannerFeedback
from orchestration.planner_agent import PlannerAgent
from orchestration.phase3_orchestrator import Phase3Orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ==========================================
# MOCK LLM: Simulates learning from mistakes
# ==========================================
class MockLLM:
    def __init__(self, test_case: dict):
        self.test_case = test_case
        self.call_count = 0

    def generate(self, prompt: str, max_tokens: int = 2048) -> str:
        self.call_count += 1
        has_feedback = "PREVIOUS ATTEMPT FAILED" in prompt

        if not has_feedback:
            plan = self.test_case["broken_plan"]
            logger.info(f"  [MockLLM] Iteration {self.call_count}: Returning BROKEN plan")
        else:
            plan = self.test_case["fixed_plan"]
            logger.info(f"  [MockLLM] Iteration {self.call_count}: Returning FIXED plan (learned from feedback)")

        return f"```json\n{json.dumps(plan, indent=2)}\n```"


# ==========================================
# TEST CASES: Broken -> Fixed plans
# ==========================================
PLANNER_TEST_CASES = {
    "eval_v3.py": {
        "description": "Eval injection - Math Engine",
        "broken_plan": {
            "sep": {"target_id": "CWE-95-v3", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": [], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_evalv3_plan", "strategy": "stdio"},
            "aep": {"tries": [{"input": "__import__('os').system('touch /tmp/pwned_evalv3_plan')", "response": None}]},
            # BROKEN: wrong benign_response (the app prints "Answer: 42", not "Result: 42")
            "fep": {"tries": [{"input": "42\n", "response": "Result: 42"}]},
        },
        "fixed_plan": {
            "sep": {"target_id": "CWE-95-v3", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": [], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_evalv3_plan", "strategy": "stdio"},
            "aep": {"tries": [{"input": "__import__('os').system('touch /tmp/pwned_evalv3_plan')", "response": None}]},
            # FIXED: correct response string
            "fep": {"tries": [{"input": "42\n", "response": "Answer: 42"}]},
        },
    },
    "sqli_v2.py": {
        "description": "SQL Injection - Product Search",
        "broken_plan": {
            "sep": {"target_id": "CWE-89-v2", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": [], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_sqliv2_plan", "strategy": "stdio"},
            # BROKEN: payload doesn't use ATTACH DATABASE
            "aep": {"tries": [{"input": "' OR 1=1 --", "response": None}]},
            "fep": {"tries": [{"input": "widget\n", "response": "Search complete"}]},
        },
        "fixed_plan": {
            "sep": {"target_id": "CWE-89-v2", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": [], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_sqliv2_plan", "strategy": "stdio"},
            # FIXED: uses ATTACH DATABASE to create the file
            "aep": {"tries": [{"input": "x'; ATTACH DATABASE '/tmp/pwned_sqliv2_plan' AS pwn; --", "response": None}]},
            "fep": {"tries": [{"input": "widget\n", "response": "Search complete"}]},
        },
    },
    "yaml_v2.py": {
        "description": "YAML Deserialization - Config Parser",
        "broken_plan": {
            "sep": {"target_id": "CWE-502-YAML-v2", "image": "python:3.9-slim",
                    "working_dir": "/app",
                    # BROKEN: missing PyYAML dependency
                    "dependencies": [], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_yamlv2_plan", "strategy": "stdio"},
            "aep": {"tries": [{"input": "!!python/object/apply:os.system [\"touch /tmp/pwned_yamlv2_plan\"]", "response": None}]},
            "fep": {"tries": [{"input": "key: value\n", "response": "Config loaded"}]},
        },
        "fixed_plan": {
            "sep": {"target_id": "CWE-502-YAML-v2", "image": "python:3.9-slim",
                    "working_dir": "/app",
                    # FIXED: added PyYAML
                    "dependencies": ["pip:PyYAML"], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_yamlv2_plan", "strategy": "stdio"},
            "aep": {"tries": [{"input": "!!python/object/apply:os.system [\"touch /tmp/pwned_yamlv2_plan\"]", "response": None}]},
            "fep": {"tries": [{"input": "key: value\n", "response": "Config loaded"}]},
        },
    },
    "mako_v4.py": {
        "description": "Mako Template Injection - Label Printer",
        "broken_plan": {
            "sep": {"target_id": "CWE-94-MAKO-v4", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": ["pip:Mako"], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_makov4_plan", "strategy": "stdio"},
            # BROKEN: wrong payload syntax (missing $)
            "aep": {"tries": [{"input": "{__import__('os').system('touch /tmp/pwned_makov4_plan')}", "response": None}]},
            "fep": {"tries": [{"input": "Widget X", "response": "Product: Widget X"}]},
        },
        "fixed_plan": {
            "sep": {"target_id": "CWE-94-MAKO-v4", "image": "python:3.9-slim",
                    "working_dir": "/app", "dependencies": ["pip:Mako"], "setup_commands": [], "services": []},
            "cep": {"success_file": "/tmp/pwned_makov4_plan", "strategy": "stdio"},
            # FIXED: correct Mako expression syntax
            "aep": {"tries": [{"input": "${__import__('os').system('touch /tmp/pwned_makov4_plan')}", "response": None}]},
            "fep": {"tries": [{"input": "Widget X", "response": "Product: Widget X"}]},
        },
    },
}


# ==========================================
# MAIN
# ==========================================
def main():
    args = sys.argv[1:]
    quick = "--quick" in args

    if quick:
        test_names = ["eval_v3.py", "sqli_v2.py"]
    else:
        test_names = list(PLANNER_TEST_CASES.keys())

    results = []
    total_pass = 0

    print("\n=== VAITP PHASE 3: PLANNER SELF-CORRECTION LOOP TEST ===\n")

    for filename in test_names:
        tc = PLANNER_TEST_CASES[filename]
        print(f"\n{'='*60}")
        print(f"  TEST: {filename} ({tc['description']})")
        print(f"  Scenario: LLM returns broken plan -> gets feedback -> fixes it")
        print(f"{'='*60}")

        mock_llm = MockLLM(tc)
        planner = PlannerAgent(llm_generate_fn=mock_llm.generate)
        orchestrator = Phase3Orchestrator(planner=planner)

        vuln_path = f"vaitp_dataset/vulnerable/{filename}"
        patch_path = f"vaitp_dataset/injectable/{filename}"

        if not os.path.exists(vuln_path):
            print(f"  SKIP: {vuln_path} not found")
            continue

        with open(vuln_path) as f:
            vuln_code = f.read()
        with open(patch_path) as f:
            patch_code = f.read()

        report = orchestrator.run_with_planner(
            test_name=f"planner_{filename}",
            vuln_code=vuln_code,
            patch_code=patch_code,
            vuln_description=tc["description"],
            vuln_path=vuln_path,
            patch_path=patch_path,
            max_iterations=3,
        )

        if report.passed:
            total_pass += 1
            status = f"\033[92mPASS (converged on iteration {report.iteration})\033[0m"
        else:
            status = f"\033[91mFAIL ({', '.join(report.failure_reasons)})\033[0m"

        print(f"\n  Result: {status}")
        print(f"  LLM calls: {mock_llm.call_count}")
        print(f"  Total time: {report.total_time:.2f}s")
        results.append(report)

    print(f"\n{'='*60}")
    print(f"  PLANNER LOOP SUMMARY: {total_pass}/{len(results)} tests converged")
    print(f"{'='*60}")

    for r in results:
        color = "\033[92m" if r.passed else "\033[91m"
        reset = "\033[0m"
        print(f"  {r.test_name:<30} | {color}{r.verdict.value:<15}{reset} | iter {r.iteration}")

    sys.exit(0 if total_pass == len(results) else 1)


if __name__ == "__main__":
    main()
