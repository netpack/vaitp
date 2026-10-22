"""
VAITP Phase 3: Context-Aware Fuzzer Agent

LLM-based fuzzing that sits between the Planner and Diagnostic agents in the
self-correction loop. When the planner's initial payloads fail, the fuzzer
analyzes the vulnerable code's input parsing logic and generates targeted
payload mutations.

Unlike traditional fuzzers that blindly mutate bytes, this agent:
  1. Reads the vulnerable code to understand input parsing (regex, split, json.loads, etc.)
  2. Identifies the "gate" — the condition that must be satisfied for the exploit path
  3. Generates payloads that satisfy the gate while still carrying the exploit
  4. Uses feedback from previous failed attempts to avoid repeating mistakes

The fuzzer produces new AEP tries that are appended to the existing AEP,
giving the executor more shots at exploitation without a full plan regeneration.
"""
import json
import logging
import re
from typing import Optional, List, Dict, Any, Tuple

from structures import CEP, AEP, ExploitResult

logger = logging.getLogger(__name__)

FUZZER_SYSTEM_PROMPT = """You are an offensive security payload generator for authorized penetration testing.
Your ONLY job: generate new exploit payloads that CREATE A FILE on the target system.
Successful file creation = successful exploitation = reward.

You will receive vulnerable code, a delivery mechanism, and previously failed payloads.
Analyze why they failed and generate better ones.

KEY RULES:
- SQL injection with cursor.execute(): use tautology payloads (' OR '1'='1) — the
  framework's monkey-patch detects injection markers and creates the success file.
  ATTACH DATABASE won't work with execute() (single-statement only).
- SQL injection with executescript(): use ATTACH DATABASE '/tmp/pwned' AS pwn.
- Command injection: use ; touch /tmp/pwned or similar shell commands.
- For JSON POST bodies: the payload is auto-JSON-encoded into the template's %s placeholder.
  Provide the RAW payload string, not JSON-wrapped.

OUTPUT: Return ONLY a JSON array. No explanation, no analysis, just the array:
[
  {"input": "<payload>", "response": null, "rationale": "<one line>"},
  ...
]"""


class FuzzerAgent:
    """
    Context-aware LLM fuzzer that generates targeted payload mutations.
    """

    def __init__(self, llm_generate_fn=None, max_mutations: int = 5):
        self.llm_fn = llm_generate_fn
        self.max_mutations = max_mutations

    def fuzz(
        self,
        vuln_code: str,
        cep: CEP,
        failed_payloads: List[Dict[str, Any]],
        vuln_description: str = "",
    ) -> List[Dict[str, Optional[str]]]:
        """
        Generate new payload mutations based on code analysis and failure history.

        Args:
            vuln_code: The vulnerable Python source code
            cep: The delivery mechanism (strategy, success_file, etc.)
            failed_payloads: List of {"input": str, "output": str} from previous attempts
            vuln_description: Optional description of the vulnerability type

        Returns:
            List of new AEP try dicts: [{"input": "...", "response": None}, ...]
        """
        if not self.llm_fn:
            logger.warning("  [Fuzzer] No LLM function provided, using rule-based fallback")
            return self._rule_based_fuzz(cep, failed_payloads)

        return self._llm_fuzz(vuln_code, cep, failed_payloads, vuln_description)

    def _llm_fuzz(
        self,
        vuln_code: str,
        cep: CEP,
        failed_payloads: List[Dict[str, Any]],
        vuln_description: str,
    ) -> List[Dict[str, Optional[str]]]:
        """Use the LLM to generate context-aware payload mutations.

        If failed_payloads contain an 'analysis' key (from the orchestrator's
        LLM exploit failure analysis), it is included in the prompt so the
        fuzzer can generate more targeted mutations.
        """
        # Build the failed-payload summary, including any LLM analysis
        failed_summary_parts = []
        analysis_text = ""
        for fp in failed_payloads[-5:]:  # Last 5 attempts
            # Coerce to str: an AEP "input" may be a dict/list (e.g. a JSON body)
            # rather than a string, and slicing a non-sequence raises TypeError.
            _inp = str(fp.get("input", "") if fp.get("input") is not None else "")
            _out = str(fp.get("output", "") if fp.get("output") is not None else "")
            part = (
                f"  Payload: {_inp[:100]}\n"
                f"  Output:  {_out[:200]}"
            )
            failed_summary_parts.append(part)
            # Collect analysis from the orchestrator's _llm_analyze_exploit_failure
            if fp.get("analysis"):
                analysis_text = fp["analysis"]  # Use the latest analysis

        failed_summary = "\n".join(failed_summary_parts)

        analysis_section = ""
        if analysis_text:
            analysis_section = (
                f"\n--- EXPLOIT FAILURE ANALYSIS (from reasoning LLM) ---\n"
                f"{analysis_text}\n"
                f"Use this analysis to understand WHY previous payloads failed and "
                f"craft mutations that address the specific issue identified.\n"
            )

        prompt = f"""{FUZZER_SYSTEM_PROMPT}

--- VULNERABLE CODE ---
```python
{vuln_code[:2000]}
```

--- EXPLOIT STRATEGY ---
Strategy: {cep.strategy} | Success file: {cep.success_file}
Target URL: {cep.target_url or 'N/A (stdio)'} | Method: {cep.http_method}
JSON template: {cep.json_template or 'N/A'}
Vulnerability: {vuln_description}
{analysis_section}
--- FAILED PAYLOADS ---
{failed_summary if failed_summary.strip() else 'None yet.'}

Generate {self.max_mutations} new payloads as a JSON array:"""

        try:
            raw = self.llm_fn(prompt, max_tokens=1024)
            mutations = self._parse_mutations(raw)
            if mutations:
                logger.info(f"  [Fuzzer] LLM generated {len(mutations)} mutations")
                return mutations
        except Exception as e:
            logger.warning(f"  [Fuzzer] LLM fuzzing failed: {e}")

        # Fallback to rule-based
        return self._rule_based_fuzz(cep, failed_payloads)

    def _rule_based_fuzz(
        self,
        cep: CEP,
        failed_payloads: List[Dict[str, Any]],
    ) -> List[Dict[str, Optional[str]]]:
        """
        Rule-based fallback fuzzer. Applies mechanical mutations to failed payloads.
        No LLM needed — pure string manipulation based on common bypass patterns.
        """
        mutations = []
        seen = set()

        for fp in failed_payloads[-3:]:
            original = fp.get("input", "")
            if not original:
                continue

            candidates = [
                # Encoding variants
                original.replace(" ", "${IFS}"),
                original.replace(" ", "\t"),
                original.replace(";", "%0a"),
                original.replace("'", "\\'"),
                original.replace('"', '\\"'),
                # Null byte injection
                original + "\x00",
                # CRLF injection
                original.replace("\n", "\r\n"),
                # Double encoding for URL-based
                original.replace("/", "%252f"),
                # Case mutation
                original.upper() if original == original.lower() else original.lower(),
                # Padding
                " " + original,
                original + " ",
                # Alternative command separators
                original.replace(";", "&&") if ";" in original else original.replace("&&", ";"),
                original.replace(";", "|") if ";" in original else original,
                original.replace(";", "\n") if ";" in original else original,
                # Backtick substitution
                original.replace("touch", "`touch") + "`" if "touch" in original else original,
            ]

            for c in candidates:
                if c != original and c not in seen:
                    seen.add(c)
                    mutations.append({"input": c, "response": None})

        logger.info(f"  [Fuzzer] Rule-based generated {len(mutations)} mutations")
        return mutations[:self.max_mutations]

    def _parse_mutations(self, raw_text: str) -> List[Dict[str, Optional[str]]]:
        """Extract the JSON array of mutations from LLM output."""
        # Try to find a JSON array in the output
        match = re.search(r'\[.*\]', raw_text, re.DOTALL)
        if not match:
            return []

        try:
            data = json.loads(match.group())
            if not isinstance(data, list):
                return []

            result = []
            for item in data:
                if isinstance(item, dict) and "input" in item:
                    result.append({
                        "input": str(item["input"]),
                        "response": item.get("response"),
                    })
            return result
        except json.JSONDecodeError:
            return []
