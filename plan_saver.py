"""
VAITP: Plan Saver
Persists CEP/AEP/FEP/SEP plans to generated_plans/ after verification.

Directory structure:
    generated_plans/
        exploited/          # Latest passing result per test (quick lookup)
            <test_name>.json
        failed/             # Latest failing result per test (quick lookup)
            <test_name>.json
        attempts/           # ALL attempts, versioned — never deleted (training data)
            <test_name>_v1.json
            <test_name>_v2.json
            ...
"""
import json
import os
import glob
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

PLANS_DIR = "generated_plans"
EXPLOITED_DIR = os.path.join(PLANS_DIR, "exploited")
FAILED_DIR = os.path.join(PLANS_DIR, "failed")
ATTEMPTS_DIR = os.path.join(PLANS_DIR, "attempts")


def _dataclass_to_dict(obj) -> Dict[str, Any]:
    """Convert a dataclass to a JSON-serializable dict, dropping None/empty values."""
    if not hasattr(obj, '__dict__'):
        return obj
    d = {}
    for k, v in obj.__dict__.items():
        if v is None or v == "" or v == []:
            continue
        d[k] = v
    return d


def _next_attempt_version(stem: str) -> int:
    """Find the next available version number for a test's attempts."""
    os.makedirs(ATTEMPTS_DIR, exist_ok=True)
    existing = glob.glob(os.path.join(ATTEMPTS_DIR, f"{stem}_v*.json"))
    if not existing:
        return 1
    versions = []
    for path in existing:
        base = os.path.basename(path).replace(".json", "")
        # e.g. "flask_nosql_1_v3" -> extract "3"
        parts = base.rsplit("_v", 1)
        if len(parts) == 2 and parts[1].isdigit():
            versions.append(int(parts[1]))
    return max(versions, default=0) + 1


def _build_payload(test_name, report, sep, cep, aep, fep, metadata):
    """Build the JSON payload dict from a report and plans."""
    if isinstance(report, dict):
        timing = {
            "provision_s": round(report.get("provision_s", 0), 2),
            "functional_s": round(report.get("functional_s", 0), 2),
            "security_s": round(report.get("security_s", 0), 2),
            "total_s": round(report.get("total_s", 0), 2),
        }
        verdict = report.get("verdict", "UNKNOWN")
        passed = report.get("passed", False)
        failure_reasons = report.get("failure_reasons", [])
        iteration = report.get("iteration", 0)
    else:
        timing = {
            "provision_s": round(getattr(report, "provision_time", 0), 2),
            "functional_s": round(getattr(report, "functional_time", 0), 2),
            "security_s": round(getattr(report, "security_time", 0), 2),
            "total_s": round(getattr(report, "total_time", 0), 2),
        }
        verdict_obj = getattr(report, "verdict", "UNKNOWN")
        verdict = verdict_obj.value if hasattr(verdict_obj, "value") else str(verdict_obj)
        passed = getattr(report, "passed", False)
        failure_reasons = getattr(report, "failure_reasons", [])
        iteration = getattr(report, "iteration", 0)

    payload = {
        "test_name": test_name,
        "verdict": verdict,
        "passed": passed,
        "failure_reasons": failure_reasons,
        "iteration": iteration,
        "saved_at": datetime.now().isoformat(),
        "sep": _dataclass_to_dict(sep),
        "cep": _dataclass_to_dict(cep),
        "aep": _dataclass_to_dict(aep),
        "fep": _dataclass_to_dict(fep),
        "timing": timing,
    }
    if metadata:
        payload["metadata"] = metadata
    return payload, passed


def save_plans(
    test_name: str,
    report,
    sep,
    cep,
    aep,
    fep,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Save plans to disk.

    Two things happen on every call:
      1. The attempt is appended to attempts/<stem>_v<N>.json (never overwritten).
      2. The latest result is written to exploited/ or failed/ (overwritten each run).
         When a test flips from failed→exploited, the old failed/ file is removed
         (and vice-versa) so the quick-lookup dirs stay clean.

    Returns:
        Path to the saved attempt JSON, or None on error.
    """
    payload, passed = _build_payload(test_name, report, sep, cep, aep, fep, metadata)
    stem = os.path.splitext(test_name)[0]

    try:
        # --- 1. Append to attempts/ (training data, never deleted) ---
        version = _next_attempt_version(stem)
        payload["attempt_version"] = version
        os.makedirs(ATTEMPTS_DIR, exist_ok=True)
        attempt_path = os.path.join(ATTEMPTS_DIR, f"{stem}_v{version}.json")
        with open(attempt_path, 'w') as f:
            json.dump(payload, f, indent=2, default=str)

        # --- 2. Write to exploited/ or failed/ (latest result) ---
        target_dir = EXPLOITED_DIR if passed else FAILED_DIR
        os.makedirs(target_dir, exist_ok=True)
        latest_path = os.path.join(target_dir, f"{stem}.json")
        with open(latest_path, 'w') as f:
            json.dump(payload, f, indent=2, default=str)

        # Clean opposite directory if verdict flipped
        opposite_dir = FAILED_DIR if passed else EXPLOITED_DIR
        opposite_path = os.path.join(opposite_dir, f"{stem}.json")
        if os.path.exists(opposite_path):
            os.remove(opposite_path)

        logger.info(f"  Plans saved → {attempt_path} + {latest_path}")
        return attempt_path
    except Exception as e:
        logger.error(f"  Failed to save plans: {e}")
        return None


# ==========================================
# LOADERS
# ==========================================
def load_proven_plans() -> Dict[str, Dict[str, Any]]:
    """Load all proven-exploitable plans from exploited/."""
    return _load_dir(EXPLOITED_DIR)


def load_failed_plans() -> Dict[str, Dict[str, Any]]:
    """Load all latest-failed plans from failed/."""
    return _load_dir(FAILED_DIR)


def load_all_attempts(test_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Load attempt history from attempts/.

    Args:
        test_name: If given (e.g. "flask_nosql_1.py"), only load attempts for
                   that test. Otherwise load everything.

    Returns:
        List of attempt dicts, sorted by (test_name, attempt_version).
    """
    attempts = []
    if not os.path.isdir(ATTEMPTS_DIR):
        return attempts

    stem_filter = os.path.splitext(test_name)[0] if test_name else None

    for fname in sorted(os.listdir(ATTEMPTS_DIR)):
        if not fname.endswith(".json"):
            continue
        if stem_filter and not fname.startswith(stem_filter + "_v"):
            continue
        fpath = os.path.join(ATTEMPTS_DIR, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            attempts.append(data)
        except Exception as e:
            logger.warning(f"  Could not load {fpath}: {e}")

    attempts.sort(key=lambda a: (a.get("test_name", ""), a.get("attempt_version", 0)))
    return attempts


def _load_dir(directory: str) -> Dict[str, Dict[str, Any]]:
    """Load all JSON plans from a directory, keyed by test_name."""
    plans = {}
    if not os.path.isdir(directory):
        return plans
    for fname in os.listdir(directory):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            test_name = data.get("test_name", fname.replace(".json", ".py"))
            plans[test_name] = data
        except Exception as e:
            logger.warning(f"  Could not load {fpath}: {e}")
    return plans


# ==========================================
# FORMATTING FOR LLM CONTEXT
# ==========================================
def format_proven_plan_as_example(plan_data: Dict[str, Any]) -> str:
    """Format a proven plan as a compact few-shot example string for LLM context.
    
    Keeps examples small to avoid blowing up the context window:
    - AEP inputs are truncated to 80 chars
    - Generator scripts are summarized, not included verbatim
    - JSON is compact (no indent)
    """
    cep = plan_data.get("cep", {})
    aep = plan_data.get("aep", {})
    fep = plan_data.get("fep", {})
    sep = plan_data.get("sep", {})
    rationale = cep.get("exploit_rationale", "")

    # Compact SEP: only key fields
    sep_compact = {
        "image": sep.get("image", "python:3.9-slim"),
        "dependencies": sep.get("dependencies", []),
    }
    if sep.get("services"):
        sep_compact["services"] = [{"image": s.get("image"), "alias": s.get("alias")} for s in sep.get("services", [])]

    # Compact CEP: only key fields
    cep_compact = {
        "strategy": cep.get("strategy", "stdio"),
        "success_file": cep.get("success_file", "/tmp/pwned"),
    }
    if cep.get("target_url"):
        cep_compact["target_url"] = cep["target_url"]
    if cep.get("http_method") and cep.get("strategy") == "network":
        cep_compact["http_method"] = cep["http_method"]
    if cep.get("json_template"):
        cep_compact["json_template"] = cep["json_template"]
    if cep.get("http_headers"):
        cep_compact["http_headers"] = cep["http_headers"]

    # Compact AEP: truncate inputs, summarize generators
    aep_tries = []
    for t in aep.get("tries", [])[:2]:  # Max 2 tries shown
        if t.get("generator"):
            aep_tries.append({"generator": "(script)", "response": None})
        elif t.get("craft_file"):
            aep_tries.append({"craft_file": "(file)", "input": t.get("input", "")[:60], "response": None})
        else:
            inp = t.get("input", "")
            aep_tries.append({"input": inp[:80], "response": None})
    aep_compact = {"tries": aep_tries}

    # Compact FEP: just first try
    fep_tries = fep.get("tries", [{"input": "", "response": ""}])[:1]
    fep_compact = {"tries": fep_tries}

    return (
        f"--- Proven Example: {plan_data.get('test_name', 'unknown')} ---\n"
        f"Strategy: {cep_compact['strategy']} | Success: {cep_compact['success_file']}\n"
        f"Rationale: {rationale[:150]}\n"
        f"SEP: {json.dumps(sep_compact, default=str)}\n"
        f"CEP: {json.dumps(cep_compact, default=str)}\n"
        f"AEP: {json.dumps(aep_compact, default=str)}\n"
        f"FEP: {json.dumps(fep_compact, default=str)}\n"
    )


def format_failed_attempt_as_warning(attempt_data: Dict[str, Any]) -> str:
    """Format a failed attempt as a compact negative example for LLM context."""
    cep = attempt_data.get("cep", {})
    aep = attempt_data.get("aep", {})
    reasons = attempt_data.get("failure_reasons", [])

    # Only show first payload, truncated
    first_input = ""
    for t in aep.get("tries", []):
        raw = t.get("input", "")
        first_input = str(raw)[:80]
        if first_input:
            break

    return (
        f"--- Failed: {attempt_data.get('test_name', 'unknown')} ---\n"
        f"Strategy: {cep.get('strategy', 'stdio')} | Reasons: {', '.join(reasons)}\n"
        f"Payload tried: {first_input}\n"
        f"DO NOT repeat this approach.\n"
    )
