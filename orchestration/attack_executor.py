"""
VAITP Phase 3: Attack Executor
Ported from run_all_poc_tests.py (Ground Truth).
Handles both CLI (stdio) and Network attack strategies with
Base64 encoding, curl construction, and file-based verification.
"""
import base64
import json
import time
import logging
import urllib.parse
from typing import Optional

from structures import SEP, CEP, AEP, FEP, FunctionalResult, ExploitResult

logger = logging.getLogger(__name__)


class AttackExecutor:
    """
    Executes functional and security checks against a provisioned container.
    Implements the Double-Check Methodology:
      - run_functional_check: Benign input -> expects normal output
      - run_exploit_check: Malicious input -> expects side-effect file creation
    """

    @staticmethod
    def _check_container_running(container) -> bool:
        """Return True if the container is still running, False otherwise."""
        try:
            container.reload()
            return container.status == "running"
        except Exception:
            return False

    # ==========================================
    # CURL CONSTRUCTION (Network Strategy)
    # ==========================================
    def _prepare_curl(self, cep: CEP, input_data: str) -> str:
        """
        Build a curl command string for network-based attacks.
        Handles: GET params, POST JSON, multipart uploads, header injection,
        cookie injection, and PAYLOAD_PLACEHOLDER substitution.
        """
        # Ensure input_data is always a string
        if not isinstance(input_data, str):
            input_data = str(input_data) if input_data is not None else ""
        curl_cmd = "curl -s"

        # --- Header logic ---
        payload_consumed_by_header = False

        if cep.http_headers:
            for key, val in cep.http_headers.items():
                if "PAYLOAD_PLACEHOLDER" in val:
                    payload_consumed_by_header = True
                    safe_data = input_data.replace("'", "'\\''")
                    header_val = val.replace("PAYLOAD_PLACEHOLDER", safe_data)
                else:
                    header_val = val
                curl_cmd += f" -H '{key}: {header_val}'"

        # --- Body / URL logic ---
        if cep.multipart_filename:
            curl_cmd += f' -F "file=@/etc/hostname;filename={input_data}"'
            url = cep.target_url

        elif cep.http_method == "POST":
            curl_cmd += " -X POST -H 'Content-Type: application/json'"
            if cep.json_template:
                try:
                    # Determine if %s is inside JSON quotes or bare.
                    # Bare %s (e.g. {"user": %s}) needs the payload JSON-encoded
                    # so the result is valid JSON: {"user": "' OR '1'='1"}.
                    # Quoted %s (e.g. {"cmd": "%s"}) already has quotes — just
                    # substitute the raw string.
                    template = cep.json_template
                    # Safety: coerce dict to JSON string if LLM output was wrong type
                    if isinstance(template, dict):
                        template = json.dumps(template)
                    pct_idx = template.find('%s')
                    bare_placeholder = False
                    if pct_idx >= 0:
                        # Check if %s is preceded by a quote char (inside a string)
                        before = template[:pct_idx].rstrip()
                        after = template[pct_idx + 2:].lstrip()
                        # Bare if the char before %s is not a quote and char after is not a quote
                        # e.g. {"key": %s, ...} → bare   vs  {"key": "%s", ...} → quoted
                        bare_placeholder = (
                            (not before or before[-1] not in ('"', "'"))
                            and (not after or after[0] not in ('"', "'"))
                        )

                    if bare_placeholder:
                        # Check if input is already a valid JSON value (dict, list,
                        # number, bool, null). If so, substitute directly — it's
                        # already a valid JSON fragment (e.g. NoSQL {"$ne": ""}).
                        stripped_input = input_data.strip()
                        already_json = False
                        if stripped_input and (stripped_input[0] in ('{', '[', 't', 'f', 'n') or stripped_input[:1].isdigit()):
                            try:
                                json.loads(stripped_input)
                                already_json = True
                            except (json.JSONDecodeError, ValueError):
                                pass

                        if already_json:
                            body = template % stripped_input
                        else:
                            # JSON-encode the payload so it becomes a valid JSON value
                            # e.g. ' OR '1'='1  →  "' OR '1'='1"
                            body = template % json.dumps(input_data)
                    else:
                        body = template % input_data
                except TypeError:
                    # No %s in template. If input looks like JSON, use it as the body.
                    # Otherwise fall back to the static template.
                    stripped = input_data.strip()
                    if stripped.startswith('{') or stripped.startswith('['):
                        body = stripped
                    else:
                        body = cep.json_template
                # Shell-escape the entire body (replace ' with '\'' for safe embedding)
                safe_body = body.replace("'", "'\\''")
                curl_cmd += f" -d '{safe_body}'"
            url = cep.target_url

        else:
            if payload_consumed_by_header:
                url = cep.target_url
            else:
                encoded_data = urllib.parse.quote(input_data)
                target = cep.target_url
                # Safety net: if the URL doesn't end with '=' (no query param ready
                # for payload), warn. The LLM should include the param name in the URL
                # e.g. http://127.0.0.1:5000/user?username=
                if '?' not in target and not target.endswith('/'):
                    logger.warning(
                        f"  [WARN] target_url '{target}' has no query params for GET. "
                        f"Payload will be appended to path. LLM should include ?param= in URL."
                    )
                url = f"{target}{encoded_data}"

        curl_cmd += f" '{url}'"
        return curl_cmd
    # ==========================================
    # PAYLOAD PREPARATION (Generators & Crafted Files)
    # ==========================================
    def _prepare_payload(self, container, trial: dict) -> str:
        """
        Resolve the actual payload for a trial.

        If the trial has a "generator" field, the Python script is executed inside
        the container and its stdout becomes the payload. This handles complex
        binary payloads (pickle, zip, custom formats) that are hard to express
        as static strings.

        If the trial has a "craft_file" field, the file is written into the
        container before the exploit runs. The "input" field then typically
        references this file path.

        Returns the resolved payload string.
        """
        # Step 1: Write any crafted files into the container
        craft = trial.get("craft_file")
        if craft:
            self._write_craft_file(container, craft)

        # Step 2: Resolve the payload
        generator = trial.get("generator")
        if generator:
            return self._run_generator(container, generator)

        payload = trial.get("input", "")
        if isinstance(payload, list):
            payload = payload[0] if payload else ""
        return str(payload) if payload is not None else ""

    def _run_generator(self, container, generator_script: str) -> str:
        """
        Run a Python generator script inside the container.
        The script's stdout is captured and returned as the payload.

        The generator script can use any libraries installed in the container.
        It should print() the final payload to stdout (raw string, hex, or base64
        depending on what the delivery mechanism expects).
        """
        # Auto-fix missing imports: LLMs frequently use stdlib modules without
        # importing them. Detect usage and prepend missing import statements.
        _auto_imports = {
            "base64": "import base64",
            "json": "import json",
            "pickle": "import pickle",
            "os": "import os",
            "sys": "import sys",
            "io": "import io",
            "struct": "import struct",
            "hashlib": "import hashlib",
            "hmac": "import hmac",
            "urllib": "import urllib.parse",
            "tarfile": "import tarfile",
            "zipfile": "import zipfile",
        }
        prepend_lines = []
        for mod, imp_stmt in _auto_imports.items():
            # Check if module is used but not imported
            if mod + "." in generator_script or mod + "(" in generator_script:
                if f"import {mod}" not in generator_script and f"from {mod}" not in generator_script:
                    prepend_lines.append(imp_stmt)
        if prepend_lines:
            generator_script = "\n".join(prepend_lines) + "\n" + generator_script

        import base64 as b64mod
        encoded = b64mod.b64encode(generator_script.encode('utf-8')).decode('utf-8')
        cmd = f'sh -c "echo {encoded} | base64 -d | python -u"'
        res = container.exec_run(cmd)
        output = res.output.decode('utf-8', errors='ignore').strip()
        if res.exit_code != 0:
            logger.warning(f"  [Generator] Script exited with code {res.exit_code}")
            logger.warning(f"  [Generator] Output: {output[:200]}")
        else:
            logger.info(f"  [Generator] Produced payload ({len(output)} chars)")
        return output

    def _write_craft_file(self, container, craft: dict):
        """
        Write a crafted file into the container.

        craft dict format:
          {"path": "/app/evil.xml", "content": "<xml>...</xml>"}
          or
          {"path": "/app/evil.bin", "generator": "import struct; ..."}

        For generator-based craft files, the script's stdout is written to the path.
        """
        path = craft["path"]
        content = craft.get("content")
        generator = craft.get("generator")

        if generator:
            # Run generator, capture output, write to file
            import base64 as b64mod
            encoded = b64mod.b64encode(generator.encode('utf-8')).decode('utf-8')
            cmd = f'sh -c "echo {encoded} | base64 -d | python -u > {path}"'
            res = container.exec_run(cmd)
            if res.exit_code != 0:
                err = res.output.decode('utf-8', errors='ignore')[:200]
                logger.warning(f"  [CraftFile] Generator failed for {path}: {err}")
            else:
                logger.info(f"  [CraftFile] Generated {path}")
        elif content:
            import base64 as b64mod
            encoded = b64mod.b64encode(content.encode('utf-8')).decode('utf-8')
            cmd = f'sh -c "echo {encoded} | base64 -d > {path}"'
            container.exec_run(cmd)
            logger.info(f"  [CraftFile] Wrote {path} ({len(content)} bytes)")

    # ==========================================
    # NETWORK SERVICE MANAGEMENT
    # ==========================================
    def _start_network_service(self, container, script_name: str):
        """Start a Flask/network service. Aggressive pkill first to free ports."""
        container.exec_run("pkill -9 -f python")
        time.sleep(1)
        # Ensure port 5000 is free before starting
        container.exec_run("sh -c 'fuser -k 5000/tcp 2>/dev/null || true'")
        time.sleep(0.5)
        container.exec_run(
            f"sh -c 'nohup python -u {script_name} > /tmp/server.log 2>&1 &'"
        )
        # Wait for Flask to actually start listening (up to 8 seconds)
        for _ in range(16):
            time.sleep(0.5)
            check = container.exec_run("sh -c 'curl -s -o /dev/null -w \"%{http_code}\" http://127.0.0.1:5000/ 2>/dev/null || echo 000'")
            code = check.output.decode('utf-8', errors='ignore').strip()
            if code != '000':
                break
        else:
            logger.warning("  [Network] Flask may not have started within 8s")

    def _stop_network_service(self, container):
        """Kill all python processes in the container."""
        container.exec_run("pkill -9 -f python")

    # ==========================================
    # FUNCTIONAL CHECK (Benign Input)
    # ==========================================
    @staticmethod
    def _looks_like_crash(output: str, strategy: str) -> bool:
        """Return True if the output exhibits an unhandled-exception / crash
        signature, so a benign functional check cannot be satisfied by a crash.

        Detects:
          - a Python traceback (uncaught exception),
          - the scaffold's caught-exception marker line ('ERROR: ...'),
          - an HTTP 500 / Internal Server Error (network strategy).
        These indicate the benign operation did not actually succeed.
        """
        o = output or ""
        if "Traceback (most recent call last)" in o:
            return True
        for line in o.splitlines():
            if line.strip().startswith("ERROR:"):
                return True
        if strategy == "network":
            if "500 Internal Server Error" in o or "Internal Server Error" in o:
                return True
        return False

    def run_functional_check(self, container, script_name: str, cep: CEP, fep: FEP) -> FunctionalResult:
        """
        Run the script with benign input(s) and verify expected output.
        Golden Rule: If this fails, the test is INVALID (infrastructure failure).
        FEP provides tries with input/response pairs; CEP provides delivery mechanism.
        Runs all checks and reports each individually before returning.
        ALL tries must pass.
        """
        from trace_diagram import get_tracer
        _tr = get_tracer()
        logger.info(f"  [Functional] Checking {script_name}...")
        total = len(fep.tries)
        all_outputs = []
        failed_checks = []
        error = None

        try:
            if not self._check_container_running(container):
                logger.error(f"  [Functional] Container is not running — skipping functional check for {script_name}")
                return FunctionalResult(
                    script_name=script_name, passed=False, output="",
                    expected=", ".join(str(t.get("response", "")) or "" for t in fep.tries),
                    error="Container not running",
                )

            for i, trial in enumerate(fep.tries):
                benign_input = str(trial.get("input", "") or "")
                benign_response = str(trial.get("response", "") or "")
                label = f"[{i+1}/{total}]" if total > 1 else ""
                display_input = benign_input.strip()[:60]
                output = ""

                if cep.strategy == "stdio":
                    output = self._run_stdio(container, script_name, benign_input)
                    curl_cmd = None

                elif cep.strategy == "network":
                    self._start_network_service(container, script_name)
                    curl_cmd = self._prepare_curl(cep, benign_input)
                    res = container.exec_run(curl_cmd)
                    curl_out = res.output.decode('utf-8', errors='ignore')

                    # Retry once on 500 — MySQL connection warmup can cause
                    # the first request to fail after start/stop cycles
                    if '500 Internal Server Error' in curl_out:
                        logger.info(f"  [Functional] Got 500, retrying after 3s...")
                        time.sleep(3)
                        res = container.exec_run(curl_cmd)
                        curl_out = res.output.decode('utf-8', errors='ignore')

                    log_res = container.exec_run("cat /tmp/server.log")
                    server_log = log_res.output.decode('utf-8', errors='ignore')
                    output = curl_out + "\n" + server_log

                    self._stop_network_service(container)

                all_outputs.append(output)

                # Strip any VAITP instrumentation prefixes that may interfere
                # with FEP response matching (e.g., from stdio side-effect wrapper)
                output_clean = output
                for _prefix in ["STDOUT_VULNERABLE:", "VAITP_DETECTED:", "STDERR_VULNERABLE:"]:
                    output_clean = output_clean.replace(_prefix, "")

                # A benign functional check must reflect that the program actually
                # WORKED on benign input — not that it crashed. Otherwise a plan can
                # "pass" the functional check by setting the expected response to the
                # program's own error/crash text. Reject outputs that exhibit an
                # unhandled-exception signature even if the expected substring matches.
                crashed = self._looks_like_crash(output_clean, cep.strategy)

                if benign_response and benign_response in output_clean and not crashed:
                    logger.info(f"  \033[92m  [+] {label} PASS: input='{display_input}' → found '{benign_response}'\033[0m")
                    _tr.trace_docker_exec(f"Functional {label} PASS", script_name,
                                          result={"verdict": "PASS", "strategy": cep.strategy,
                                                  "command": curl_cmd, "input": benign_input,
                                                  "expected": benign_response, "output": output})
                else:
                    fail_reason = "expected substring not found"
                    if crashed and benign_response and benign_response in output_clean:
                        fail_reason = "benign input crashed (error/exception in output); a crash cannot count as functional correctness"
                    elif crashed:
                        fail_reason = "benign input crashed (error/exception in output)"
                    logger.warning(f"  \033[91m  [-] {label} FAIL: input='{display_input}' → {fail_reason}\033[0m")
                    _tr.trace_docker_exec(f"Functional {label} FAIL", script_name,
                                          result={"verdict": "FAIL", "strategy": cep.strategy,
                                                  "command": curl_cmd, "input": benign_input,
                                                  "expected": benign_response, "output": output,
                                                  "reason": fail_reason})
                    logger.warning(f"      Strategy: {cep.strategy}")
                    if cep.strategy == "network":
                        logger.warning(f"      URL: {cep.target_url} | Method: {cep.http_method}")
                    output_snippet = output.strip()[:300] if output.strip() else "<empty>"
                    logger.warning(f"      Actual output:")
                    for line in output_snippet.splitlines():
                        logger.warning(f"        | {line}")
                    failed_checks.append((i, benign_input, benign_response, output))

        except Exception as e:
            error = str(e)
            logger.error(f"  [Functional] Error: {e}")

        combined_output = "\n".join(all_outputs)
        passed = len(failed_checks) == 0 and error is None

        if passed:
            logger.info(f"  \033[92m  [+] All {total} functional check(s) passed\033[0m")
        else:
            logger.warning(f"  \033[91m  Summary: {total - len(failed_checks)}/{total} passed, {len(failed_checks)}/{total} failed\033[0m")

        # Return the first failure's expected value for reporting
        first_failed_expected = failed_checks[0][2] if failed_checks else ", ".join(str(t.get("response", "")) or "" for t in fep.tries)

        return FunctionalResult(
            script_name=script_name,
            passed=passed,
            output=combined_output,
            expected=first_failed_expected,
            error=error,
        )

    # ==========================================
    # EXPLOIT CHECK (Malicious Input)
    # ==========================================
    def run_exploit_check(self, container, script_name: str, cep: CEP, aep: AEP) -> ExploitResult:
        """
        Run the script with malicious input(s) and check for side-effect file.
        Golden Rule: Never rely on stdout. Always use file creation (test -f).
        Any single successful try is enough to prove exploitation.

        Supports:
          - Static payloads (input field)
          - Generator scripts (generator field → runs in container, stdout = payload)
          - Crafted files (craft_file field → written to container before exploit)
        """
        from trace_diagram import get_tracer
        _tr = get_tracer()
        logger.info(f"  [Security] Attacking {script_name}...")
        total = len(aep.tries)
        all_outputs = []
        error = None

        try:
            if not self._check_container_running(container):
                logger.error(f"  [Security] Container is not running — skipping exploit check for {script_name}")
                return ExploitResult(
                    script_name=script_name, exploited=False,
                    success_file=cep.success_file, output="",
                    error="Container not running",
                )

            for i, trial in enumerate(aep.tries):
                label = f"[{i+1}/{total}]" if total > 1 else ""

                # Bail out early if the container died mid-loop
                if i > 0 and not self._check_container_running(container):
                    logger.error(f"  [Security] Container died during exploit check — aborting remaining payloads")
                    error = "Container stopped mid-test"
                    break

                # Resolve payload (may run generator or write craft files)
                payload = self._prepare_payload(container, trial)
                display_payload = str(payload).strip()[:60] if payload else "<empty>"
                output = ""

                container.exec_run(f"rm -f {cep.success_file}")

                if cep.strategy == "stdio":
                    output = self._run_stdio(container, script_name, payload)
                    curl_cmd = None

                elif cep.strategy == "network":
                    self._start_network_service(container, script_name)
                    curl_cmd = self._prepare_curl(cep, payload)
                    res = container.exec_run(curl_cmd)
                    output = res.output.decode('utf-8', errors='ignore')
                    self._stop_network_service(container)
                else:
                    curl_cmd = None

                all_outputs.append(output)

                check = container.exec_run(f"test -f {cep.success_file}")
                if check.exit_code == 0:
                    logger.info(f"  \033[93m  [!] {label} VULNERABLE: payload='{display_payload}' → file created\033[0m")
                    _tr.trace_docker_exec(f"Exploit {label} VULNERABLE", script_name,
                                          result={"verdict": "VULNERABLE", "strategy": cep.strategy,
                                                  "command": curl_cmd, "payload": payload,
                                                  "output": output, "success_file": cep.success_file})
                    if total > 1:
                        logger.info(f"  \033[93m  Exploitation succeeded on payload {i+1}/{total}, skipping remaining\033[0m")
                    return ExploitResult(
                        script_name=script_name,
                        exploited=True,
                        success_file=cep.success_file,
                        output=output,
                        error=error,
                    )
                else:
                    logger.info(f"  \033[92m  [-] {label} Safe: payload='{display_payload}' → no file created\033[0m")
                    _tr.trace_docker_exec(f"Exploit {label} SAFE", script_name,
                                          result={"verdict": "SAFE", "strategy": cep.strategy,
                                                  "command": curl_cmd, "payload": payload,
                                                  "output": output})

        except Exception as e:
            error = str(e)
            logger.error(f"  [Security] Error: {e}")
            _tr.trace_error("Docker", f"Exploit check error: {e}")

        logger.info(f"  \033[92m  [+] SAFE — none of {total} payload(s) created {cep.success_file}\033[0m")
        return ExploitResult(
            script_name=script_name,
            exploited=False,
            success_file=cep.success_file,
            output="\n".join(all_outputs),
            error=error,
        )

    # ==========================================
    # STDIO EXECUTION (Base64 Wrapper)
    # ==========================================
    def _run_stdio(self, container, script_name: str, input_data: str) -> str:
        """
        Execute a CLI script by piping input via Base64 encoding.
        Avoids shell escaping issues with special characters.
        """
        raw = input_data
        if not raw.endswith('\n'):
            raw += '\n'

        b64 = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
        cmd = f'sh -c "echo {b64} | base64 -d | python -u {script_name}"'

        res = container.exec_run(cmd)
        return res.output.decode('utf-8', errors='ignore')
