#!/usr/bin/env python3
"""
VAITP Phase 3: Full Dataset Verification Runner

Runs the Phase 3 Double-Check Methodology across ALL files in vaitp_dataset/.
For each test file:
  1. If a gold standard plan exists (TEST_REGISTRY or mutation_registry), use it.
  2. Otherwise, use the LLM PlannerAgent to generate plans.
  3. On failure, run the DiagnosticAgent for self-correction.
  4. Previously proven plans (from generated_plans/exploited/) are loaded as
     learning context so the LLM can exploit new vulnerabilities faster.
  5. All results are saved to generated_plans/exploited/ or generated_plans/failed/.

Usage:
    python run_phase3.py                              # Full run, gold standard + LLM
    python run_phase3.py --gold-only                  # Only run gold standard tests
    python run_phase3.py --llm-only                   # Only run LLM-generated tests
    python run_phase3.py --model deepseek-r1:14b      # Specify LLM model
    python run_phase3.py --max-iterations 5           # More self-correction attempts
    python run_phase3.py --filter flask_ssti           # Only run tests matching pattern
    python run_phase3.py --skip-proven                 # Skip already-proven tests
    python run_phase3.py --resume                      # Skip proven + already-failed
"""
import sys
import os
import json
import time
import logging
import argparse
from typing import Dict, Any, List, Optional, Tuple

from structures import SEP, CEP, AEP, FEP, VerificationReport, TestVerdict
from orchestration.phase3_orchestrator import Phase3Orchestrator
from orchestration.planner_agent import PlannerAgent
from orchestration.diagnostic_agent import DiagnosticAgent
from orchestration.fuzzer_agent import FuzzerAgent
from plan_saver import (
    save_plans, load_proven_plans, load_failed_plans, load_all_attempts,
    format_proven_plan_as_example, format_failed_attempt_as_warning,
)
from config import LOCAL_LLM_TIMEOUT, HEALTH_CHECK_TIMEOUT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def _log_command_line(log_file: str = "orchestrator_run.log"):
    """Write the exact invocation command as the first line of the log file."""
    import shlex
    cmd_line = " ".join(shlex.quote(a) for a in sys.argv)
    # Prepend to existing content (or create the file)
    existing = ""
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            existing = f.read()
    with open(log_file, "w") as f:
        f.write(f"$ {cmd_line}\n{existing}")

DATASET_DIR = "vaitp_dataset"
DEFAULT_MODEL = "deepseek-r1:14b"

# ==========================================
# DISPLAY HELPERS
# ==========================================
C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[1m"
DIM = "\033[2m"


def _cleanup_leftover_containers():
    """Remove any leftover VAITP Docker containers after a run.
    
    Catches containers that weren't properly cleaned up due to errors,
    by looking for containers attached to the vaitp_net network or
    running from vaitp-cache images.
    """
    try:
        import docker as _docker
        client = _docker.from_env()
        removed = 0

        for c in client.containers.list(all=True):
            try:
                # Check if container is on the vaitp network
                networks = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                on_vaitp_net = "vaitp_net" in networks

                # Check if container uses a vaitp-cache image
                tags = c.image.tags if c.image.tags else []
                uses_cache_image = any("vaitp-cache" in t for t in tags)

                if on_vaitp_net or uses_cache_image:
                    c.remove(force=True)
                    removed += 1
            except Exception:
                pass

        if removed:
            logger.info(f"  Cleaned up {removed} leftover VAITP container(s)")
        client.close()
    except Exception as e:
        logger.warning(f"  Docker cleanup warning: {e}")
X = "\033[0m"


def section(title: str, color: str = C):
    print(f"\n{color}{'=' * 78}")


def _load_intended_vuln(filename: str) -> Optional[Dict]:
    """Load the intended vulnerability info for a test file from Phase 1 plans.
    Returns dict with 'type', 'expected_pattern' etc., or None if not found."""
    base = os.path.splitext(filename)[0]

    # Handle variant filenames: "flask_sqli_1__variant_0" → "flask_sqli_1"
    original_base = base
    if '__variant_' in base:
        original_base = base.split('__variant_')[0]

    # Search common prompts directories for Phase 1 plan files.
    # Phase 1 saves plans to directories like:
    #   - prompts/
    #   - generated_prompts/
    #   - generated_prompts_{experiment}_{model}/  (e.g. generated_prompts_PromSec_..._deepseek-r1:14b/)
    search_dirs = ["prompts", "generated_prompts"]
    # Also scan workspace root for any generated_prompts_* directories
    workspace_root = os.path.dirname(os.path.abspath(__file__))
    try:
        for entry in os.listdir(workspace_root):
            if entry.startswith("generated_prompts_") and os.path.isdir(os.path.join(workspace_root, entry)):
                search_dirs.append(entry)
    except OSError:
        pass

    plan_name = f"{base}_plan.json"
    # Also try the original base name for variant files
    plan_names = [plan_name]
    if original_base != base:
        plan_names.append(f"{original_base}_plan.json")
    for root_dir in search_dirs:
        if os.path.isdir(root_dir):
            for dirpath, _, filenames in os.walk(root_dir):
                for pn in plan_names:
                    if pn in filenames:
                        try:
                            with open(os.path.join(dirpath, pn)) as f:
                                plan = json.load(f)
                            return plan.get("intended_vuln", {})
                        except Exception:
                            pass

    # Fallback: infer vulnerability type from filename patterns
    # Use original_base for variant files so pattern matching works
    fn = (original_base if original_base != base else filename).lower()
    vuln_map = [
        ("flask_nosql_real", {"type": "Flask NoSQL Injection with MongoDB (CWE-943)"}),
        ("flask_nosql", {"type": "Flask NoSQL Injection (CWE-943)"}),
        ("flask_ssti", {"type": "Flask SSTI (CWE-1336)"}),
        ("flask_json", {"type": "Flask JSON Command Injection (CWE-78)"}),
        ("flask_upload", {"type": "Flask Upload Path Traversal (CWE-22)"}),
        ("flask_header", {"type": "Flask Header Command Injection (CWE-78)"}),
        ("flask_pickle", {"type": "Flask Pickle Deserialization (CWE-502)"}),
        ("flask_ssrf", {"type": "Flask SSRF (CWE-918)"}),
        ("flask_jwt", {"type": "Flask JWT Algorithm Confusion (CWE-345)"}),
        ("flask_sqli", {"type": "Flask SQL Injection (CWE-89)"}),
        ("flask_", {"type": "Flask Command Injection (CWE-78)"}),
        ("sqli", {"type": "SQL Injection (CWE-89)"}),
        ("eval", {"type": "Code Injection via eval() (CWE-95)"}),
        ("pickle", {"type": "Insecure Deserialization via pickle (CWE-502)"}),
        ("ssti", {"type": "Server-Side Template Injection (CWE-1336)"}),
        ("yaml", {"type": "YAML Deserialization (CWE-502)"}),
        ("mako", {"type": "Mako Template Injection (CWE-94)"}),
        ("xslt", {"type": "XSLT Injection (CWE-91)"}),
        ("zip", {"type": "Path Traversal / Zip Slip (CWE-22)"}),
        ("1167", {"type": "OS Command Injection via subprocess (CWE-78)"}),
        ("360", {"type": "GitPython Command Injection (CVE-2022-24439)"}),
        ("478", {"type": "OS Command Injection (CWE-78)"}),
        ("1_1", {"type": "Open Redirect (CWE-601)"}),
    ]
    for pattern, vuln_info in vuln_map:
        if pattern in fn:
            return vuln_info
    return None
    print(f"  {title}")
    print(f"{'=' * 78}{X}\n")


# ==========================================
# GOLD STANDARD REGISTRY LOADER
# ==========================================
def load_gold_standard_registry() -> Dict[str, Dict[str, Any]]:
    """
    Merge the base TEST_REGISTRY (from run_all_poc_tests.py) and the
    mutation_registry into a single dict of gold standard plans.
    """
    registry = {}

    # 1. Load base test registry
    try:
        from run_all_poc_tests import TEST_REGISTRY
        for filename, config in TEST_REGISTRY.items():
            registry[filename] = config
        #logger.info(f"  Loaded {len(TEST_REGISTRY)} base tests from TEST_REGISTRY")
    except ImportError as e:
        logger.warning(f"  Could not import TEST_REGISTRY: {e}")

    # 2. Load mutation registry
    try:
        from gold_standard.mutation_registry import get_mutation_registry
        mutations = get_mutation_registry()
        for filename, config in mutations.items():
            registry[filename] = config
        #logger.info(f"  Loaded {len(mutations)} mutation tests from mutation_registry")
    except ImportError as e:
        logger.warning(f"  Could not import mutation_registry: {e}")

    return registry


# ==========================================
# DATASET SCANNER
# ==========================================
def ensure_dataset_populated():
    """Ensure vaitp_dataset/vulnerable and injectable directories are populated.
    
    Copies files from outros/ if the main dataset directories are empty or missing files.
    The vulnerable files will be validated and repaired by the LLM repair loop.
    The injectable (patched) files are the safe starting point and don't need repair.
    """
    outros_vuln = os.path.join(DATASET_DIR, "outros", "vulnerable")
    outros_patch = os.path.join(DATASET_DIR, "outros", "injectable")
    vuln_dir = os.path.join(DATASET_DIR, "vulnerable")
    patch_dir = os.path.join(DATASET_DIR, "injectable")

    if not os.path.isdir(outros_vuln) or not os.path.isdir(outros_patch):
        return  # No outros directory, nothing to copy

    import shutil
    os.makedirs(vuln_dir, exist_ok=True)
    os.makedirs(patch_dir, exist_ok=True)

    copied_vuln = 0
    copied_patch = 0

    # Copy injectable (patched/safe) files — these are the ground truth
    for fn in os.listdir(outros_patch):
        if fn.endswith(".py"):
            dst = os.path.join(patch_dir, fn)
            if not os.path.exists(dst):
                shutil.copy2(os.path.join(outros_patch, fn), dst)
                copied_patch += 1

    # Copy vulnerable files as starting point — will be validated & repaired
    for fn in os.listdir(outros_vuln):
        if fn.endswith(".py"):
            dst = os.path.join(vuln_dir, fn)
            if not os.path.exists(dst):
                shutil.copy2(os.path.join(outros_vuln, fn), dst)
                copied_vuln += 1

    if copied_vuln or copied_patch:
        logger.info(f"  Dataset init: copied {copied_vuln} vulnerable, {copied_patch} injectable files from outros/")


def scan_dataset() -> List[str]:
    """Find all test files that have both vulnerable and injectable versions."""
    vuln_dir = os.path.join(DATASET_DIR, "vulnerable")
    patch_dir = os.path.join(DATASET_DIR, "injectable")

    if not os.path.isdir(vuln_dir) or not os.path.isdir(patch_dir):
        logger.error(f"Dataset directories not found: {vuln_dir}, {patch_dir}")
        return []

    vuln_files = {f for f in os.listdir(vuln_dir) if f.endswith(".py")}
    patch_files = {f for f in os.listdir(patch_dir) if f.endswith(".py")}
    paired = sorted(vuln_files & patch_files)
    #logger.info(f"  Found {len(paired)} paired test files in dataset")
    return paired


# ==========================================
# LLM LOADER
# ==========================================
def create_ollama_fn(model_key: str, stream_llm: bool = False):
    """Create a generate function that uses Ollama's HTTP API.
    Much faster than llama-cpp for models already loaded in Ollama.

    If stream_llm=True, tokens are displayed live in the StreamDisplay bottom pane.
    """
    import requests

    OLLAMA_URL = "http://localhost:11434/api/generate"

    # Verify the model is available (retry with generous timeout — Ollama may
    # be slow to respond after a long generation in a previous phase)
    try:
        resp = None
        for _attempt in range(3):
            try:
                resp = requests.get("http://localhost:11434/api/tags", timeout=HEALTH_CHECK_TIMEOUT)
                resp.raise_for_status()
                break
            except (requests.ReadTimeout, requests.ConnectionError) as retry_err:
                if _attempt < 2:
                    logger.warning(f"Ollama health check attempt {_attempt + 1}/3 failed ({retry_err}), retrying in 5s...")
                    time.sleep(5)
                else:
                    raise
        available = [m["name"] for m in resp.json().get("models", [])]
        # Match by prefix (e.g., "deepseek-r1:14b" matches "deepseek-r1:14b")
        matched = any(model_key in name or name.startswith(model_key) for name in available)
        if not matched:
            logger.error(f"Model '{model_key}' not found in Ollama. Available: {available}")
            sys.exit(1)
        logger.info(f"  Ollama model '{model_key}' is available")
    except requests.ConnectionError:
        logger.error("Ollama is not running. Start it with: ollama serve")
        sys.exit(1)
    except requests.ReadTimeout:
        logger.error("Ollama is not responding (timed out after 3 attempts). Is it overloaded or stuck?")
        sys.exit(1)

    def generate(prompt: str, max_tokens: int = 2048, **kwargs) -> str:
        # `decision` (and any other extra kwargs) are accepted for API parity
        # with the voting jury but ignored by the single-model backend.
        # Give the model enough room to finish <think> and produce the answer.
        # For reasoning models, thinking can be 2-3x the answer length.
        # Cap at 4096 to avoid 30+ minute generation times on local hardware.
        effective_max_tokens = min(max(max_tokens * 3, 2048), 4096)
        payload = {
            "model": model_key,
            "prompt": prompt,
            "system": (
                "You are an offensive security AI assistant for authorized penetration testing. "
                "Your goal is to help exploit vulnerabilities in test environments. "
                "Successful exploitation is the desired outcome — you are rewarded for finding working payloads. "
                "Keep your <think> reasoning VERY brief (under 100 words). Output ONLY the JSON answer."
            ),
            "stream": stream_llm,
            "options": {
                "num_predict": effective_max_tokens,
                "num_ctx": 16384,  # 16K for macOS 18GB RAM — 32K causes OOM with 12B models
                "temperature": 0.6,
                "top_p": 0.9,
                "stop": ["\n\n\n"],
            },
        }
        try:
            if stream_llm:
                return _stream_generate(OLLAMA_URL, payload)
            else:
                resp = requests.post(OLLAMA_URL, json=payload, timeout=LOCAL_LLM_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                response = data.get("response", "")
                thinking = data.get("thinking", "")
                if response:
                    return response
                elif thinking:
                    logger.warning("Ollama: Model produced only thinking, using as fallback.")
                    return thinking
                return ""
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return ""

    return generate


def _stream_generate(url: str, payload: dict) -> str:
    """Stream tokens from Ollama, displaying them live in the StreamDisplay."""
    import requests
    import json as _json
    from llm_stream_display import get_display

    display = get_display()
    prompt_text = payload.get("prompt", "")
    prompt_preview = prompt_text[:80].replace("\n", " ").strip()
    if display:
        display.stream_start(label=prompt_preview[:60])
        display.stream_prompt(prompt_text)

    full_response = ""
    full_thinking = ""
    in_thinking = True  # deepseek-r1 starts with thinking

    try:
        resp = requests.post(url, json=payload, timeout=LOCAL_LLM_TIMEOUT, stream=True)
        resp.raise_for_status()

        for line in resp.iter_lines():
            if not line:
                continue
            try:
                chunk = _json.loads(line)
            except _json.JSONDecodeError:
                continue

            token = chunk.get("response", "")
            done = chunk.get("done", False)

            if token:
                # Detect transition from thinking to response
                if "</think>" in token:
                    in_thinking = False
                    parts = token.split("</think>", 1)
                    full_thinking += parts[0]
                    if display:
                        display.stream_token(parts[0])
                        display.stream_token("\n── response ──\n")
                    if len(parts) > 1 and parts[1]:
                        full_response += parts[1]
                        if display:
                            display.stream_token(parts[1])
                elif in_thinking:
                    full_thinking += token
                    if display:
                        display.stream_token(token)
                else:
                    full_response += token
                    if display:
                        display.stream_token(token)

            if done:
                break

    except Exception as e:
        logger.error(f"Ollama streaming error: {e}")

    if display:
        display.stream_end()

    if full_response.strip():
        return full_response.strip()
    elif full_thinking.strip():
        logger.warning("Ollama: Model produced only thinking, using as fallback.")
        return full_thinking.strip()
    return ""


def create_llm_fn(model_key: str, n_ctx_override: int = None):
    """Load a local LLM via llama-cpp and return a generate function."""
    from config import REASONING_MODELS, CODER_MODELS, LLM_N_GPU_LAYERS, LLM_N_THREADS, LLM_USE_MMAP

    model_info = REASONING_MODELS.get(model_key) or CODER_MODELS.get(model_key)
    if not model_info:
        available = list(REASONING_MODELS.keys()) + list(CODER_MODELS.keys())
        logger.error(f"Unknown model '{model_key}'. Available: {available}")
        sys.exit(1)

    model_path = model_info["path"]
    if not os.path.exists(model_path):
        logger.error(f"Model file not found: {model_path}")
        sys.exit(1)

    n_ctx = n_ctx_override or model_info.get("context_window", 8192)

    logger.info(f"Loading model: {model_key} (ctx={n_ctx})")

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
    logger.info(f"  Model loaded in {time.time() - t0:.1f}s")

    def generate(prompt: str, max_tokens: int = 2048, **kwargs) -> str:
        # Extra kwargs (e.g. `decision`) are accepted for jury API parity, ignored here.
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
# LEARNING CONTEXT BUILDER
# ==========================================
def build_learning_context(
    proven_plans: Dict[str, Dict[str, Any]],
    target_filename: str,
    target_code: str = None,
    max_examples: int = 2,
    max_warnings: int = 1,
) -> str:
    """
    Build a compact learning context string from previously proven plans.
    Kept small to avoid blowing up the LLM context window.
    """
    parts = []

    if proven_plans:
        target_base = target_filename.rsplit("_", 1)[0] if "_" in target_filename else target_filename.replace(".py", "")

        from orchestration.planner_agent import classify_vuln_from_code
        target_category = classify_vuln_from_code(target_code) if target_code else "generic"

        scored = []
        for name, plan in proven_plans.items():
            if name == target_filename:
                continue
            plan_code = plan.get("vuln_code", "")
            if plan_code:
                plan_category = classify_vuln_from_code(plan_code)
            else:
                plan_text = json.dumps(plan.get("cep", {})).lower()
                plan_category = classify_vuln_from_code(plan_text)

            score = 0
            if plan_category == target_category:
                score = 15
            plan_base = name.rsplit("_", 1)[0] if "_" in name else name.replace(".py", "")
            if plan_base == target_base:
                score = max(score, 10)
            score += 1
            scored.append((score, name, plan))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = scored[:max_examples]

        if selected:
            parts.append("--- LEARNING: proven exploits ---")
            for _, name, plan in selected:
                parts.append(format_proven_plan_as_example(plan))

    # Negative examples (compact)
    failed_attempts = [
        a for a in load_all_attempts(target_filename) if not a.get("passed", False)
    ]
    if failed_attempts:
        recent = failed_attempts[-max_warnings:]
        for attempt in recent:
            parts.append(format_failed_attempt_as_warning(attempt))

    if parts:
        return "\n".join(parts)
    return ""


# ==========================================
# SINGLE TEST RUNNER
# ==========================================
def run_single_gold_standard(
    filename: str,
    config: Dict[str, Any],
    orchestrator: Phase3Orchestrator,
) -> VerificationReport:
    """Run a single test using gold standard plans."""
    sep = config["sep"]
    cep = config["cep"]
    aep = config["aep"]
    fep = config["fep"]
    vuln_path = os.path.join(DATASET_DIR, "vulnerable", filename)
    patch_path = os.path.join(DATASET_DIR, "injectable", filename)

    return orchestrator.run_single_test(filename, sep, cep, aep, fep, vuln_path, patch_path)


def run_single_llm(
    filename: str,
    llm_fn,
    proven_plans: Dict[str, Dict[str, Any]],
    orchestrator: Optional['Phase3Orchestrator'] = None,
    max_iterations: int = 3,
    max_diag_attempts: int = 3,
    max_repair_attempts: int = 5,
    model_name: str = "unknown",
    experiment_name: str = None,
    test_timeout: int = 0,
    symmetric_hooks: bool = False,
) -> Tuple[VerificationReport, Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP]]:
    """
    Run a single test using LLM-generated plans with learning context.
    Falls back to DiagnosticAgent on failure.
    If the vulnerable code isn't actually vulnerable, attempts LLM repair.
    """
    vuln_path = os.path.join(DATASET_DIR, "vulnerable", filename)
    patch_path = os.path.join(DATASET_DIR, "injectable", filename)

    with open(vuln_path) as f:
        vuln_code = f.read()
    with open(patch_path) as f:
        patch_code = f.read()

    # --- Pre-flight: Validate that the vulnerable code actually contains the vulnerability ---
    # Load intended_vuln from Phase 1 plan if available
    intended_vuln = _load_intended_vuln(filename)
    if intended_vuln:
        from main_orchestrator import _validate_vulnerability, _repair_vulnerable_code
        is_valid, diagnosis = _validate_vulnerability(vuln_code, patch_code, intended_vuln)
        if not is_valid:
            logger.warning(f"  [Validation] {filename}: {diagnosis}")
            # Attempt LLM repair
            for attempt in range(1, max_repair_attempts + 1):
                logger.info(f"  [Repair] Attempt {attempt}/{max_repair_attempts} for {filename}...")
                from main_orchestrator import _get_vuln_pattern_guidance
                new_code = _repair_vulnerable_code(
                    patch_code, vuln_code, intended_vuln, diagnosis, llm_fn, attempt
                )
                if new_code != vuln_code:
                    is_valid, new_diag = _validate_vulnerability(new_code, patch_code, intended_vuln)
                    if is_valid:
                        logger.info(f"  [Repair] ✓ Fixed {filename} on attempt {attempt}")
                        vuln_code = new_code
                        # Save repaired code back to disk
                        with open(vuln_path, 'w') as f:
                            f.write(new_code + '\n')
                        break
                    else:
                        logger.info(f"  [Repair] Still invalid: {new_diag}")
                        vuln_code = new_code
                        diagnosis = new_diag
                else:
                    logger.info(f"  [Repair] No change on attempt {attempt}")
            else:
                logger.warning(f"  [Repair] Could not fix {filename} after {max_repair_attempts} attempts")

    # Build learning context from proven plans — pass actual code for classification
    learning_ctx = build_learning_context(proven_plans, filename, target_code=vuln_code)

    # Build a description that includes learning context
    vuln_description = f"Python vulnerability in {filename}."
    if learning_ctx:
        vuln_description += f"\n\n{learning_ctx}"

    # Phase 1: PlannerAgent with self-correction loop
    if orchestrator is None:
        planner = PlannerAgent(llm_generate_fn=llm_fn)
        fuzzer = FuzzerAgent(llm_generate_fn=llm_fn)
        orchestrator = Phase3Orchestrator(
            planner=planner, fuzzer=fuzzer,
            model_name=model_name, experiment_name=experiment_name,
            test_timeout=test_timeout,
            symmetric_hooks=symmetric_hooks,
        )

    report = orchestrator.run_with_planner(
        test_name=filename,
        vuln_code=vuln_code,
        patch_code=patch_code,
        vuln_description=vuln_description,
        vuln_path=vuln_path,
        patch_path=patch_path,
        max_iterations=max_iterations,
        proven_plans=proven_plans,
    )

    if report.passed:
        return report, report.sep, report.cep, report.aep, report.fep

    # Phase 2: DiagnosticAgent for deeper analysis
    logger.info(f"  Planner loop failed for {filename}, running DiagnosticAgent...")
    diag = DiagnosticAgent(
        llm_generate_fn=llm_fn,
        max_fix_attempts=max_diag_attempts,
        dataset_dir=DATASET_DIR,
        model_name=model_name,
        experiment_name=experiment_name,
        test_timeout=test_timeout,
        symmetric_hooks=symmetric_hooks,
    )
    final_report, final_sep, final_cep, final_aep, final_fep, fix_history = \
        diag.diagnose_and_fix(filename, report.sep, report.cep, report.aep, report.fep)

    return final_report, final_sep, final_cep, final_aep, final_fep


# ==========================================
# MAIN
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="VAITP Phase 3: Full Dataset Verification\n\n"
                    "Runs each vuln/patch pair inside Docker containers using the\n"
                    "Double-Check Methodology (functional + security checks).\n\n"
                    "ALL plans are LLM-generated. Gold standard knowledge from\n"
                    "mutation_registry is seeded as reference material so the LLM\n"
                    "can learn from it, but never used as direct execution plans.\n"
                    "This ensures the model learns, adapts, and evolves.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"LLM model for agentic planner (default: {DEFAULT_MODEL})")
    parser.add_argument("--ollama", action="store_true",
                        help="Use Ollama backend instead of llama-cpp (faster startup, no GGUF needed)")
    parser.add_argument("--vertex", action="store_true",
                        help="Use Vertex AI backend (requires gcloud auth and --vertex-config)")
    parser.add_argument("--vertex-config", type=str, default=None,
                        help="Path to Vertex AI YAML config (e.g. configs/config_deepseek.yaml)")
    parser.add_argument("--voting-config", type=str, default=None,
                        help="Path to a YAML config with a 'voting:' block. Enables the "
                             "jury (multiple juror models + judge) for allowlisted decisions.")
    parser.add_argument("--context", type=int, default=None,
                        help="Override LLM context window size (tokens)")
    parser.add_argument("--gold-only", action="store_true",
                        help="(Legacy, ignored) All tests now go through the LLM planner.")
    parser.add_argument("--llm-only", action="store_true",
                        help="(Legacy, ignored) All tests now go through the LLM planner.")
    parser.add_argument("--max-iterations", type=int, default=3,
                        help="Max planner self-correction iterations per test (default: 3)")
    parser.add_argument("--max-diag-attempts", type=int, default=3,
                        help="Max diagnostic fix attempts per failing test (default: 3)")
    parser.add_argument("--max-repair-attempts", type=int, default=5,
                        help="Max LLM repair attempts for non-vulnerable generated code (default: 5)")
    parser.add_argument("--filter", default=None,
                        help="Only run tests whose filename contains this substring (e.g. --filter flask)")
    parser.add_argument("--skip-proven", action="store_true",
                        help="Skip tests that already passed (have plans in generated_plans/exploited/)")
    parser.add_argument("--resume", action="store_true",
                        help="Skip both proven and previously-failed tests (only run untested files)")
    parser.add_argument("--stream-llm", action="store_true",
                        help="Show live LLM token output in a split terminal view (bottom pane)")
    parser.add_argument("--experiment-name", type=str, default=None,
                        help="Experiment name for DB logging (default: None)")
    parser.add_argument("--test-timeout", type=int, default=0,
                        help="Per-test timeout in seconds; 0 = no limit (default: 0)")
    parser.add_argument("--symmetric-hooks", action="store_true",
                        help="Apply the same effect-based detector to BOTH the vulnerable "
                             "and patched code (symmetric differential double-check). "
                             "Recommended for rigorous exploitability verification.")
    parser.add_argument("--phase3-test-all", action="store_true",
                        help="Test ALL Phase 2 generated codes (variant files), not just promoted best ones")
    # Trace diagram arguments (forwarded from main_orchestrator)
    parser.add_argument("--trace-diagram", action="store_true",
                        help="Generate an HTML trace report of the execution flow")
    parser.add_argument("--trace-detail-level", choices=['minimal', 'standard', 'detailed', 'full'],
                        default='standard')
    parser.add_argument("--trace-events-file", type=str, default=None,
                        help="Path to trace events JSON from parent process (internal use)")
    args = parser.parse_args()

    # Log the exact command used to invoke this script
    _log_command_line()

    # Initialize execution tracer (may load events from parent process)
    from trace_diagram import init_tracer, get_tracer
    tracer = init_tracer(
        enabled=getattr(args, 'trace_diagram', False),
        detail_level=getattr(args, 'trace_detail_level', 'standard'),
        output_dir="results",
    )
    # Load events from parent process (Phase 1/2/Promote) if available
    if args.trace_events_file and os.path.exists(args.trace_events_file):
        tracer.load_events(args.trace_events_file)
    tracer.trace_phase_start("Phase 3 - Verification", {"model": args.model})

    # Warn about legacy flags
    if args.gold_only or args.llm_only:
        logger.info("  Note: --gold-only and --llm-only are legacy flags. All tests now use the LLM planner.")

    section("VAITP PHASE 3: FULL DATASET VERIFICATION")

    # 0. Verify Docker is running (required for container-based verification)
    from docker_utils import check_docker_available
    if not check_docker_available():
        print(f"\n  {R}ERROR: Docker is not running.{X}")
        print(f"  {Y}Phase 3 requires Docker to execute tests inside containers.{X}")
        print(f"  {Y}Please start the Docker application and try again.{X}\n")
        sys.exit(1)

    # 1. Ensure dataset is populated (copy from outros/ if needed)
    ensure_dataset_populated()

    # 2. Scan dataset
    all_files = scan_dataset()
    if not all_files:
        print(f"  {R}No test files found in {DATASET_DIR}{X}")
        sys.exit(1)

    # 2. Load gold standard registry as REFERENCE MATERIAL (not direct plans)
    #    These are seeded into proven_plans so the LLM planner can learn from them,
    #    but the LLM always generates its own plans from scratch.
    gold_registry = load_gold_standard_registry()

    # 3. Load previously proven/failed plans
    proven_plans = load_proven_plans()
    failed_plans = load_failed_plans()

    # Seed gold standard knowledge into proven_plans as reference material.
    # The LLM planner uses these as few-shot examples to learn patterns,
    # but always generates its own plans adapted to the actual code.
    gold_seeded = 0
    for filename, config in gold_registry.items():
        ref_key = f"_gold_ref_{filename}"
        if ref_key not in proven_plans:
            proven_plans[ref_key] = {
                "test_name": filename,
                "sep": _config_to_dict(config["sep"]),
                "cep": _config_to_dict(config["cep"]),
                "aep": _config_to_dict(config["aep"]),
                "fep": _config_to_dict(config["fep"]),
            }
            gold_seeded += 1

    #logger.info(f"  Previously proven: {len(proven_plans) - gold_seeded}, gold standard references seeded: {gold_seeded}")
    #logger.info(f"  Previously failed: {len(failed_plans)}")

    # 4. Apply filters
    if args.filter:
        all_files = [f for f in all_files if args.filter in f]
        logger.info(f"  Filter '{args.filter}' → {len(all_files)} files")

    if args.skip_proven or args.resume:
        before = len(all_files)
        all_files = [f for f in all_files if f not in proven_plans]
        logger.info(f"  Skipping {before - len(all_files)} already-proven tests")

    if args.resume:
        before = len(all_files)
        all_files = [f for f in all_files if f not in failed_plans]
        logger.info(f"  Skipping {before - len(all_files)} already-failed tests")

    total = len(all_files)
    print(f"  Total files to test: {total}")
    print()

    if total == 0:
        print(f"  {Y}Nothing to run.{X}")
        sys.exit(0)

    # 5. Initialize stream display if requested
    if args.stream_llm:
        from llm_stream_display import init_display
        _disp = init_display(append=True)
        _disp.set_phase("Phase 3")

    # 6. Load LLM (always needed — all plans are LLM-generated)
    section("LOADING LLM")
    if args.vertex or getattr(args, 'vertex_config', None):
        from vertex_backend import create_vertex_fn, load_vertex_config
        vcfg_path = args.vertex_config
        if not vcfg_path:
            logger.error("--vertex requires --vertex-config <path>")
            sys.exit(1)
        vcfg = load_vertex_config(vcfg_path)
        logger.info(f"  Vertex AI model: {vcfg['model']}")
        logger.info(f"  Vertex AI endpoint: {vcfg['api_base']}")
        llm_fn = create_vertex_fn(model=vcfg['model'], api_base=vcfg['api_base'])
        # Override model name for logging/DB
        args.model = vcfg['model']
    elif args.ollama:
        llm_fn = create_ollama_fn(args.model, stream_llm=args.stream_llm)
    else:
        llm_fn = create_llm_fn(args.model, n_ctx_override=args.context)

    # Wrap LLM for automatic tracing of all calls
    from trace_diagram import wrap_llm_for_tracing
    llm_fn = wrap_llm_for_tracing(llm_fn, args.model, "Phase 3 - Exploitation planning & verification")

    # 6b. Optional jury (multi-model voting). When enabled, allowlisted
    #     decisions are decided by a panel of jurors + a judge instead of the
    #     single model above. Non-allowlisted calls go to the primary juror.
    planner_fn = fuzzer_fn = base_fn = llm_fn
    jury = None
    if getattr(args, 'voting_config', None):
        from orchestration.voting_jury import load_voting_config, build_jury
        vote_cfg = load_voting_config(args.voting_config)
        jury = build_jury(vote_cfg, tracer=tracer)
        if jury is not None:
            args.model = vote_cfg.label()
            logger.info(f"  Jury enabled: jurors={jury.juror_ids}, "
                        f"decisions={list(vote_cfg.decisions.keys())}")
            # Planner gets an UNTAGGED fn; PlannerAgent tags each call site
            # explicitly (phase3.plan.infrastructure/payloads/edit). Only those
            # tags (plus phase3.recovery) are allowlisted, so hooks/diagnostics/
            # repairs run on the primary juror alone.
            planner_fn = jury.make_fn()
            fuzzer_fn = jury.make_fn("phase3.fuzz")
            base_fn = jury.make_fn()  # untagged -> primary juror (repair/diagnostic)
        else:
            logger.warning("  --voting-config provided but voting is disabled/empty; "
                           "falling back to single model.")

    # 6. Run ALL tests through the LLM planner
    results = []
    planner = PlannerAgent(llm_generate_fn=planner_fn)
    fuzzer = FuzzerAgent(llm_generate_fn=fuzzer_fn)
    orchestrator = Phase3Orchestrator(
        planner=planner, fuzzer=fuzzer,
        model_name=args.model,
        experiment_name=getattr(args, 'experiment_name', None),
        test_timeout=getattr(args, 'test_timeout', 0),
        symmetric_hooks=getattr(args, 'symmetric_hooks', False),
    )
    total_start = time.time()

    section(f"LLM-PLANNED TESTS ({total} files)")
    for i, filename in enumerate(all_files, 1):
        has_gold_ref = filename in gold_registry
        ref_tag = " [gold ref]" if has_gold_ref else ""
        print(f"  [{i}/{total}] {filename}{ref_tag} ... ", end="", flush=True)
        t0 = time.time()
        try:
            report, sep, cep, aep, fep = run_single_llm(
                filename, base_fn, proven_plans,
                orchestrator=orchestrator,
                max_iterations=args.max_iterations,
                max_diag_attempts=args.max_diag_attempts,
                max_repair_attempts=args.max_repair_attempts,
                model_name=args.model,
                experiment_name=getattr(args, 'experiment_name', None),
                test_timeout=getattr(args, 'test_timeout', 0),
                symmetric_hooks=getattr(args, 'symmetric_hooks', False),
            )
            elapsed = time.time() - t0
            status = f"{G}PASS{X}" if report.passed else f"{R}FAIL ({', '.join(report.failure_reasons)}){X}"
            print(f"{status} ({elapsed:.1f}s)")

            # Trace the test result
            if report.passed:
                tracer.trace_docker_exec("PASS", filename,
                                         result={"verdict": "PASS"},
                                         duration=elapsed)
            else:
                tracer.trace_docker_exec("FAIL", filename,
                                         result={"verdict": "FAIL",
                                                 "reasons": report.failure_reasons[:3]},
                                         duration=elapsed)

            results.append({"name": filename, "source": "llm", "passed": report.passed,
                            "failure_reasons": report.failure_reasons, "time": elapsed})

            # Add to proven plans for subsequent tests (cumulative learning)
            if report.passed and filename not in proven_plans and cep:
                proven_plans[filename] = {
                    "test_name": filename,
                    "sep": _config_to_dict(sep),
                    "cep": _config_to_dict(cep),
                    "aep": _config_to_dict(aep),
                    "fep": _config_to_dict(fep),
                }
        except Exception as e:
            elapsed = time.time() - t0
            # Abort the entire run on fatal Vertex AI errors (model not found, etc.)
            from vertex_backend import VertexFatalError
            if isinstance(e, VertexFatalError):
                print(f"{R}FATAL: {e}{X} ({elapsed:.1f}s)")
                print(f"\n  {R}Aborting run — this error is not retryable.{X}")
                tracer.trace_error("Orchestrator", f"FATAL: {e}")
                results.append({"name": filename, "source": "llm", "passed": False,
                                "failure_reasons": [str(e)], "time": elapsed})
                break
            print(f"{R}ERROR: {e}{X} ({elapsed:.1f}s)")
            tracer.trace_error("Orchestrator", f"{filename}: {e}")
            results.append({"name": filename, "source": "llm", "passed": False,
                            "failure_reasons": [str(e)], "time": elapsed})

    # 7. Shutdown and final report
    orchestrator.shutdown()
    _cleanup_leftover_containers()

    # Shut down stream display before printing final report to real stdout
    if args.stream_llm:
        from llm_stream_display import shutdown_display
        shutdown_display()

    total_duration = time.time() - total_start
    section("FINAL REPORT")

    total_pass = sum(1 for r in results if r["passed"])

    print(f"  Passed: {total_pass}/{total}")
    print(f"  Duration: {total_duration:.1f}s")
    print()

    # Detailed table
    print(f"  {'FILE':<30} {'STATUS':<35} {'TIME':>8}")
    print(f"  {'-'*30} {'-'*35} {'-'*8}")
    for r in results:
        color = G if r["passed"] else R
        status = "PASS" if r["passed"] else f"FAIL ({', '.join(r['failure_reasons'][:2])})"
        if len(status) > 35:
            status = status[:32] + "..."
        print(f"  {r['name']:<30} {color}{status:<35}{X} {r['time']:>6.1f}s")
    print()

    # Summary of generated_plans
    final_proven = load_proven_plans()
    final_failed = load_failed_plans()
    all_attempts = load_all_attempts()
    passed_attempts = sum(1 for a in all_attempts if a.get("passed", False))
    failed_attempts = len(all_attempts) - passed_attempts
    print(f"  generated_plans/exploited/: {len(final_proven)} files")
    print(f"  generated_plans/failed/:    {len(final_failed)} files")
    print(f"  generated_plans/attempts/:  {len(all_attempts)} total ({passed_attempts} passed, {failed_attempts} failed)")
    print()

    # Render trace diagram (includes Phase 1/2/Promote events from parent process)
    tracer.trace_phase_end("Phase 3 - Verification", {
        "total": total, "passed": total_pass,
        "duration": total_duration,
    })
    if tracer.enabled:
        trace_path = tracer.render()
        if trace_path:
            print(f"📊 Execution trace saved to: {trace_path}")
        # Clean up handoff file
        if args.trace_events_file and os.path.exists(args.trace_events_file):
            try:
                os.remove(args.trace_events_file)
            except OSError:
                pass

    sys.exit(0 if total_pass == total else 1)


def _config_to_dict(obj) -> Dict:
    """Convert a dataclass or dict to a plain dict."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, '__dict__'):
        return {k: v for k, v in obj.__dict__.items() if v is not None and v != "" and v != []}
    return {}


if __name__ == "__main__":
    main()
