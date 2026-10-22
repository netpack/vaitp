#!/usr/bin/env python3
"""
Smoke test for Vertex AI models used in Phase-3-vertex-sven-pyvul-1504.

Tests each model with a simple prompt to verify:
1. Authentication (gcloud token) works
2. Model endpoint is reachable
3. Model returns a valid response
"""

import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vertex_backend import create_vertex_fn, load_vertex_config, VertexFatalError, _call_vertex_chat

MODELS = [
    {
        "name": "Gemini 3.1 Pro Preview",
        "config": "configs/Phase-3-vertex-sven-pyvul-1504_gemini.yaml",
    },
    {
        "name": "DeepSeek R1-0528",
        "config": "configs/Phase-3-vertex-sven-pyvul-1504_deepseek.yaml",
    },
    {
        "name": "Qwen3-235B",
        "config": "configs/Phase-3-vertex-sven-pyvul-1504_qwen.yaml",
    },
]

SMOKE_PROMPT = (
    "You are a security testing assistant. "
    "Analyze this Python code and identify the vulnerability type (CWE):\n\n"
    "```python\n"
    "import sqlite3\n"
    "def get_user(username):\n"
    "    conn = sqlite3.connect('users.db')\n"
    "    cursor = conn.cursor()\n"
    "    cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\n"
    "    return cursor.fetchone()\n"
    "```\n\n"
    "Reply with ONLY the CWE ID and a one-line description."
)


def smoke_test_model(model_info: dict) -> bool:
    """Test a single model. Returns True on success."""
    name = model_info["name"]
    config_path = model_info["config"]

    print(f"\n{'='*60}")
    print(f"  Testing: {name}")
    print(f"  Config:  {config_path}")
    print(f"{'='*60}")

    try:
        vcfg = load_vertex_config(config_path)
        print(f"  Model ID:  {vcfg['model']}")
        print(f"  Endpoint:  {vcfg['api_base']}")

        # Call _call_vertex_chat directly to avoid sys.exit in create_vertex_fn
        print(f"  Sending smoke prompt...")
        t0 = time.time()
        response = _call_vertex_chat(
            api_base=vcfg["api_base"],
            model=vcfg["model"],
            prompt=SMOKE_PROMPT,
            max_tokens=256,
            system_prompt="You are a security testing assistant.",
        )
        elapsed = time.time() - t0

        if not response or len(response.strip()) < 5:
            print(f"  ✗ FAIL — empty or too-short response ({len(response)} chars)")
            return False

        # Check for CWE-89 mention (expected for SQL injection)
        has_cwe = "CWE-89" in response or "SQL" in response.upper()
        preview = response.strip()[:200].replace("\n", " ")

        print(f"  Response ({elapsed:.1f}s): {preview}")
        if has_cwe:
            print(f"  ✓ PASS — model correctly identified SQL injection")
        else:
            print(f"  ⚠ PASS (response received but didn't mention CWE-89/SQL)")

        return True

    except VertexFatalError as e:
        err_str = str(e)
        if "not available in region" in err_str:
            print(f"  ✗ FAIL — model not enabled for this project/region")
            print(f"    → Go to Model Garden in Cloud Console and enable the model")
            print(f"    → URL: https://console.cloud.google.com/vertex-ai/model-garden")
        elif "not found" in err_str.lower():
            print(f"  ✗ FAIL — model not found (check model ID and region)")
        else:
            print(f"  ✗ FATAL: {e}")
        return False
    except Exception as e:
        print(f"  ✗ ERROR: {type(e).__name__}: {e}")
        return False


def main():
    print("=" * 60)
    print("  VERTEX AI SMOKE TEST — Phase-3-vertex-sven-pyvul-1504")
    print("=" * 60)

    # Check gcloud auth
    print("\nChecking gcloud authentication...")
    token_check = os.popen("gcloud auth print-access-token 2>/dev/null").read().strip()
    if not token_check or "ERROR" in token_check:
        print("  ✗ gcloud auth failed. Run: gcloud auth login")
        sys.exit(1)
    print(f"  ✓ Token obtained ({len(token_check)} chars)")

    results = {}
    for model_info in MODELS:
        success = smoke_test_model(model_info)
        results[model_info["name"]] = success

    # Summary
    print(f"\n{'='*60}")
    print("  SMOKE TEST SUMMARY")
    print(f"{'='*60}")
    all_pass = True
    for name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}  {name}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("  All models passed. Ready to launch experiments.")
    else:
        print("  Some models failed. Fix issues before launching.")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
