# orchestration/attack_agents.py
import shlex
import logging, time, re, os, json, datetime
from rich.markup import escape
import docker
from llama_cpp import Llama 
from config import DOCKER_WORKDIR, DOCKER_GENERATED_CODE_FILENAME, DOCKER_SERVER_LOG_FILENAME, LOCAL_LLM_SIGNAL_TIMEOUT
from vuln_utils import ( # Import all llm_interpret_exploitation_result_* functions
    llm_interpret_exploitation_result_etcpasswd,
    llm_interpret_exploitation_result_open_redirect,
    llm_interpret_exploitation_result_jinja2,
    llm_interpret_exploitation_result_pickle,
    llm_interpret_exploitation_result_ssrf
)
from utils import clear_memory, extract_routes_and_params, clean_code # Add more utils as needed
from file_utils import create_vuln_cif_file # For specific vuln setups
from llama_cpp.llama_chat_format import LlamaChatCompletionHandler
AEP_TEMPLATES = {
    "OS Command Injection": """
# Attack Execution Plan: OS Command Injection in {target_filename}
## Objective
To confirm the 'OS Command Injection' vulnerability by executing shell commands.
## Attack Steps
- [ ] Task: [Execute 'whoami' to identify the current user]
      Action: EXECUTE[[whoami]]
- [ ] Task: [List contents of the root directory to test read access]
      Action: EXECUTE[[ls /]]
- [ ] Task: [Attempt to read the /etc/passwd file]
      Action: EXECUTE[[cat /etc/passwd]]
- [ ] Task: [Create a temporary file to test write permissions]
      Action: EXECUTE[[touch /tmp/vaitp_test_file.txt]]
- [ ] Task: [Verify the temporary file was created]
      Action: CHECK_FILE_EXISTS[[/tmp/vaitp_test_file.txt]]
- [ ] Task: [Delete the temporary file]
      Action: EXECUTE[[rm /tmp/vaitp_test_file.txt]]
""",
    "Insecure Deserialization": """
# Attack Execution Plan: Insecure Deserialization in {target_filename}
## Objective
To confirm the 'Insecure Deserialization' vulnerability by executing code via a crafted payload.
## Attack Steps
- [ ] Task: [Execute 'whoami' via a Python object payload]
      Action: EXECUTE[[!!python/object/apply:os.system ['whoami']]]
- [ ] Task: [Attempt to read /etc/passwd via a Python object payload]
      Action: EXECUTE[[!!python/object/apply:os.system ['cat /etc/passwd']]]
- [ ] Task: [Create a temporary file via a Python object payload]
      Action: EXECUTE[[!!python/object/apply:os.system ['touch /tmp/vaitp_test_file.txt']]]
- [ ] Task: [Verify the temporary file was created]
      Action: CHECK_FILE_EXISTS[[/tmp/vaitp_test_file.txt]]
- [ ] Task: [Delete the temporary file via a Python object payload]
      Action: EXECUTE[[!!python/object/apply:os.system ['rm /tmp/vaitp_test_file.txt']]]
"""
    # NOTE: We'll have 2 add more templates for other vulnerabilities here.
}

# The default template to use if a specific one isn't found.
DEFAULT_AEP_TEMPLATE = AEP_TEMPLATES["OS Command Injection"]

class AEPGenerationAgent:
    def __init__(self, llm_instance: Llama):
        self.llm = llm_instance
        logging.info("AEPGenerationAgent initialized.")

    def generate_aep(self, vulnerable_code: str, vulnerability_type: str, 
                     target_filename: str = "target.py", previous_feedback: str = None) -> str:
        
        feedback_section = ""
        if previous_feedback:
            feedback_section = f"""An earlier attempt to exploit this vulnerability with a different AEP failed. 
Your task is to generate a NEW, IMPROVED AEP that avoids the previous mistakes.
Feedback from the previous attempt: "{previous_feedback}"
Please analyze this feedback and generate a different attack strategy that strictly follows the required format.
---
"""
        # Select the correct AEP template, or fall back to the default.
        template_to_complete = AEP_TEMPLATES.get(vulnerability_type, DEFAULT_AEP_TEMPLATE)
        template_to_complete = template_to_complete.format(target_filename=target_filename)

        prompt = f"""<|im_start|>system<|im_sep|>You are a security penetration testing expert. Your task is to complete a structured Attack Execution Plan (AEP).

{feedback_section}
The vulnerable code is:
--- BEGIN OF VULNERABLE CODE ---
{vulnerable_code.strip()}
--- END OF VULNERABLE CODE ---

Your goal is to complete the following AEP template by filling in any `your_argument_here` placeholders with appropriate payloads specific to the vulnerability '{vulnerability_type}'. If the template is already complete, return it as is. Do not change the structure or add new tasks.

TEMPLATE TO COMPLETE:
---------------------
{template_to_complete}
---------------------

Your response should be ONLY the completed AEP template.
<|im_end|>
<|im_start|>user<|im_sep|>
Provide the completed AEP template now.
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
        logging.info(f"AEPGenerationAgent: Calling LLM to generate AEP. The Full prompt is:\n\n{escape(prompt)}\n")
        clear_memory()
        try:
            response = self.llm(
                prompt,
                max_tokens=2048,
                temperature=0.1,
                top_p=0.7,
                stream=False
            )
            aep_markdown = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else "# AEP Generation Failed"
            if not aep_markdown.startswith("# Attack Execution Plan"):
                aep_markdown = f"# Attack Execution Plan: {vulnerability_type} in {target_filename}\n{aep_markdown}"
            
            logging.info(f"AEPGenerationAgent: Generated AEP:\n{escape(aep_markdown)}")
            return aep_markdown
        except Exception as e:
            logging.error(f"AEPGenerationAgent: Error during LLM call: {e}")
            return f"# AEP Generation Error: {e}"

class ExecutionAgent:
    def __init__(self, llm_instance: Llama, docker_manager_instance):
        self.llm = llm_instance
        self.docker_manager = docker_manager_instance
        self.container_map = {} # To store and reuse containers for "orig_run" and "vuln_run"
        self.installed_deps = set() # To track installed dependencies
        logging.info("ExecutionAgent initialized with DockerContainerManager.")

    def _get_container_for_task(self, task_id_suffix: str):
        """
        Gets or creates a container for a specific task stream (e.g., "orig_run", "vuln_run").
        Ensures the container is running.
        """
        if task_id_suffix in self.container_map and self.container_map[task_id_suffix].status == 'running':
            logging.info(f"ExecutionAgent: Reusing container {escape(self.container_map[task_id_suffix].name)} for {escape(task_id_suffix)}")
            return self.container_map[task_id_suffix]
        
        # If not found or not running, get/create a new one via the manager
        container = self.docker_manager.get_container(identifier_suffix=task_id_suffix) # This uses the manager's logic
        if not container:
            raise Exception(f"ExecutionAgent: Could not obtain a Docker container for {task_id_suffix}")
        
        self.container_map[task_id_suffix] = container # Store for reuse by this agent instance
        return container
    
    def _execute_in_docker(self, container_for_exec, command_list_or_str, workdir=DOCKER_WORKDIR):
        """
        Executes a command in the specified Docker container.
        command_list_or_str: Can be a list of arguments (for direct exec) or a string (for sh -c).
        """
        cmd_to_log = ""
        cmd_for_exec = None

        if isinstance(command_list_or_str, list):
            cmd_to_log = " ".join(shlex.quote(arg) for arg in command_list_or_str)
            cmd_for_exec = command_list_or_str
        elif isinstance(command_list_or_str, str):
            cmd_to_log = command_list_or_str
            cmd_for_exec = ['sh', '-c', command_list_or_str] # Always wrap string commands for shell
        else:
            logging.error(f"ExecutionAgent: Invalid command type for _execute_in_docker: {type(command_list_or_str)}")
            return "", "Invalid command type", -1

        logging.info(f"ExecutionAgent: Executing in Docker ({escape(container_for_exec.name)}): {escape(cmd_to_log)}")
        
        stdout_str, stderr_str, exit_code_val = "", "", -1
        exec_result_obj = None

        try:
            exec_result_obj = container_for_exec.exec_run(cmd_for_exec, workdir=workdir, demux=True)
            
            if exec_result_obj and exec_result_obj.output is not None:
                s_out_bytes, s_err_bytes = exec_result_obj.output
                
                # For very explicit debugging of what Docker library returns
                logging.debug(f"DEBUG DockerCM: exec_result.output IS: {exec_result_obj.output}")
                logging.debug(f"DEBUG DockerCM: s_out_bytes IS: {s_out_bytes}")
                logging.debug(f"DEBUG DockerCM: s_err_bytes IS: {s_err_bytes}")

                stdout_str = s_out_bytes.decode(errors='ignore').strip() if s_out_bytes else ""
                stderr_str = s_err_bytes.decode(errors='ignore').strip() if s_err_bytes else ""
                exit_code_val = exec_result_obj.exit_code
            elif exec_result_obj:
                logging.warning(f"ExecutionAgent: Docker command exec_result.output was None. Exit code: {exec_result_obj.exit_code}")
                exit_code_val = exec_result_obj.exit_code
            else:
                logging.error("ExecutionAgent: Docker command exec_result itself was None.")
            
            if exit_code_val != 0 and not stderr_str:
                 stderr_str = f"Command exited with code {exit_code_val} but no explicit stderr captured from script."
                 logging.warning(stderr_str)

        except docker.errors.APIError as e_api:
            logging.error(f"ExecutionAgent: Docker API Error for command '{cmd_to_log}': {e_api}", exc_info=True)
            stderr_str = f"Docker API Error: {e_api}"
            exit_code_val = -2 
        except Exception as e:
            logging.error(f"ExecutionAgent: Generic error executing command '{cmd_to_log}' in Docker: {e}", exc_info=True)
            stderr_str = str(e)
            exit_code_val = -1 # General error
            
        return stdout_str, stderr_str, exit_code_val

    def parse_aep_action(self, aep_action_command: str) -> tuple[str | None, str | None]:
        """
        Parses a standardized AEP action command to extract the action type and payload.
        Expected format: "ACTION_VERB[payload]"
        e.g., "EXECUTE[whoami]", "CHECK_FILE_ABSENCE[/tmp/malicious_file]"

        Returns:
            (action_type, payload) if successful, e.g., ("EXECUTE", "whoami")
            (None, None) if the format is not recognized.
        """
        # A list of known, valid action verbs from your AEP prompt.
        KNOWN_ACTIONS = ["EXECUTE", "CHECK_FILE_EXISTS", "CHECK_FILE_ABSENCE", "ANALYZE_OUTPUT"]

        for action_verb in KNOWN_ACTIONS:
            # Regex to match content inside double square brackets
            match = re.match(rf"^\s*{action_verb}\[\[(.*?)\]\]\s*$", aep_action_command.strip())
            if match:
                payload = match.group(1).strip()
                
                # clean up payloads like "command: `whoami`"
                # This regex looks for a potential command inside backticks within the payload.
                clean_payload_match = re.search(r"`([^`]+)`", payload)
                if clean_payload_match:
                    payload = clean_payload_match.group(1).strip()
                # END of added block

                logging.info(f"ExecutionAgent: Parsed AEP action. Verb: '{escape(action_verb)}', Cleaned Payload: '{escape(payload)}'")
                return action_verb, payload
        logging.warning(f"ExecutionAgent: Could not parse AEP action command '{aep_action_command}' with any known verb.")
        return None, None # Return None explicitly if no match
    
    def parse_command_from_aep_action(self, aep_action_description: str) -> str | None:
        """
        Parses the specific command/payload meant for the target script from an AEP action line.
        The AEP is generated by an LLM, so patterns might vary.
        """
        # Pattern 1: Action: Run `payload_for_script`
        # Catches simple commands in backticks that are meant to be the direct input.
        match_direct = re.search(r"Action:\s*(?:Run|Execute)\s*(?:the\s*script\s*with|the\s*command)?\s*`([^`]+)`", aep_action_description, re.IGNORECASE)
        if match_direct:
            direct_command = match_direct.group(1).strip()
            # If this direct command itself is trying to call the script again, extract the actual payload
            # e.g., `python script.py actual_payload` -> extract `actual_payload`
            sub_match = re.search(r"python\s+[\w\._-]+\.py\s+['\"]?([^'\"`]+)['\"]?", direct_command, re.IGNORECASE)
            if sub_match:
                return sub_match.group(1).strip().strip("'\"")
            return direct_command # Assume the whole backticked content is the payload

        # Add more patterns here if AEP LLM generates different action phrasings
        logging.warning(f"ExecutionAgent: Could not parse command/payload from AEP Action: '{aep_action_description}' using known patterns.")
        return None

    def _install_dependencies_for_code(self, container, code_to_analyze: str) -> bool:
        """Copies code and installs its dependencies. Should run only once per container."""
        try:
            # Copy code to the container.
            self.docker_manager.copy_code_to_container(container, code_to_analyze, DOCKER_GENERATED_CODE_FILENAME)

            # Install pipreqs.
            logging.info(f"ExecutionAgent: Installing pipreqs in {container.name}...")
            install_pipreqs_cmd = ["python3", "-m", "pip", "install", "-q", "pipreqs"]
            exit_code, output = container.exec_run(install_pipreqs_cmd)
            if exit_code != 0:
                logging.error(f"ExecutionAgent: FAILED to install pipreqs. Exit Code: {exit_code}, Output: {output.decode(errors='ignore')}")
                return False

            # Find the full path to the installed pipreqs executable.
            find_pipreqs_cmd = ["which", "pipreqs"]
            exit_code, output = container.exec_run(find_pipreqs_cmd)
            if exit_code != 0:
                logging.error(f"ExecutionAgent: FAILED to find pipreqs executable after installation. Output: {output.decode(errors='ignore')}")
                return False
            pipreqs_path = output.decode(errors='ignore').strip()
            logging.info(f"ExecutionAgent: Found pipreqs executable at: {pipreqs_path}")

            # Run pipreqs using its full path.
            logging.info(f"ExecutionAgent: Running pipreqs in {container.name} using full path...")
            generate_reqs_cmd = [pipreqs_path, DOCKER_WORKDIR, "--force"]
            exit_code, output = container.exec_run(generate_reqs_cmd)
            if exit_code != 0:
                logging.error(f"ExecutionAgent: FAILED to run pipreqs. Exit Code: {exit_code}, Output: {output.decode(errors='ignore')}")
                return False

            # Install the generated requirements.
            logging.info(f"ExecutionAgent: Installing generated requirements in {container.name}...")
            # Check if requirements.txt exists and is not empty before trying to install.
            check_reqs_cmd = f"[ -s {DOCKER_WORKDIR}/requirements.txt ]"
            exit_code_check, _ = container.exec_run(['sh', '-c', check_reqs_cmd])
            
            if exit_code_check == 0: # File exists and has size > 0
                install_reqs_cmd = ["python3", "-m", "pip", "install", "--no-cache-dir", "-q", "-r", f"{DOCKER_WORKDIR}/requirements.txt"]
                exit_code, output = container.exec_run(install_reqs_cmd)
                if exit_code != 0:
                    logging.warning(f"ExecutionAgent: pip install from requirements.txt in {container.name} finished with exit code {exit_code}. Output: {output.decode(errors='ignore')}")
            else:
                logging.info(f"ExecutionAgent: requirements.txt is empty or not found. Skipping pip install.")


            logging.info(f"ExecutionAgent: Dependency installation process completed for {container.name}.")
            return True

        except Exception as e:
            logging.error(f"ExecutionAgent: Unhandled exception during dependency installation for {container.name}: {e}", exc_info=True)
            return False
    
    def execute_aep_task(self, aep_action_command: str, vulnerability_type: str, 
                         code_to_test_str: str, task_id_suffix: str = "task",
                         previous_task_output: str = None):

        current_container = self._get_container_for_task(task_id_suffix)
        logging.info(f"ExecutionAgent: Attempting Action Command: '{escape(aep_action_command)}' for '{escape(vulnerability_type)}' in {escape(current_container.name)}")

        #self.docker_manager.copy_code_to_container(current_container, code_to_test_str, DOCKER_GENERATED_CODE_FILENAME)

        if current_container.id not in self.installed_deps:
            if not self._install_dependencies_for_code(current_container, code_to_test_str):
                return False, f"SETUP_ERROR: Dependency installation failed for container {current_container.name}."
            self.installed_deps.add(current_container.id)

        parsed_result = self.parse_aep_action(aep_action_command)
        if parsed_result is None:
            logging.error(f"ExecutionAgent: Failed to parse action command '{aep_action_command}'. Marking task as failed.")
            return False, f"PARSE_ERROR: Could not understand action command '{aep_action_command}'"

        action_type, payload = parsed_result

        stdout, stderr, exit_code = "", "", -1
        task_successful = False
        exec_output_dict = {}

        if action_type == "EXECUTE":
            if not payload:
                stderr = "No payload provided for EXECUTE action."
                task_successful = False
            else:
                logging.info(f"ExecutionAgent: Will execute script with payload: '{escape(payload)}'")
                exec_output_dict = self.docker_manager.run_code_in_container(
                    container=current_container,
                    code_str=code_to_test_str,
                    input_str=payload
                )
                stdout = exec_output_dict.get('stdout', '')
                stderr = exec_output_dict.get('stderr', '')
                # Use the script's exit code if available, otherwise fall back to Docker's
                exit_code = exec_output_dict.get('script_exit_code')
                if exit_code is None:
                    exit_code = exec_output_dict.get('docker_exit_code', -1)
                
                task_successful = self.determine_task_success(vulnerability_type, payload, stdout, stderr, exit_code, code_version_suffix=task_id_suffix)
                
        elif action_type == "CHECK_FILE_ABSENCE":
            if not payload:
                stderr = "No filepath provided for CHECK_FILE_ABSENCE action."
                task_successful = False
            else:
                # `test ! -f` returns 0 (success) if file does NOT exist
                check_cmd = f"test ! -f {shlex.quote(payload)}"
                _, stderr, exit_code_check = self._execute_in_docker(current_container, check_cmd)
                task_successful = (exit_code_check == 0)
                stdout = f"File '{payload}' absence check: {'ABSENT (Task Success)' if task_successful else 'PRESENT or ERROR (Task Failure)'}"
        
        elif action_type == "CHECK_FILE_EXISTS":
            if not payload:
                stderr = "No filepath provided for CHECK_FILE_EXISTS action."
                task_successful = False
            else:
                # `test -f` returns 0 (success) if file EXISTS
                check_cmd = f"test -f {shlex.quote(payload)}"
                _, stderr, exit_code_check = self._execute_in_docker(current_container, check_cmd)
                task_successful = (exit_code_check == 0)
                stdout = f"File '{payload}' existence check: {'PRESENT (Task Success)' if task_successful else 'ABSENT or ERROR (Task Failure)'}"

        else:
            stderr = f"Unknown or unhandled AEP action type: '{action_type}' from command '{aep_action_command}'"
            task_successful = False
            logging.warning(f"ExecutionAgent: {stderr}")

        final_output_for_log = f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n\nEXIT_CODE: {exit_code}"
        logging.info(f"ExecutionAgent: Action '{escape(aep_action_command)}' result - Success: {escape(str(task_successful))}, OutputForInterpreter:\n{escape(final_output_for_log)}")
        
        return task_successful, final_output_for_log

    def determine_task_success(self, vulnerability_type: str, command_executed: str,
                               stdout: str, stderr: str, exit_code: int, code_version_suffix: str) -> bool:
        """
        Determines if an AEP task was successful based on its output and context.
        - For a VULNERABLE run, success means the exploit worked.
        - For an ORIGINAL run, success means the exploit was correctly PREVENTED.
        """
        is_vulnerable_run = "vuln" in code_version_suffix.lower()

        if vulnerability_type == "OS Command Injection":
            if is_vulnerable_run:
                # SUCCESS for vulnerable code is a clean run (exit code 0) with evidence of execution.
                if exit_code == 0:
                    logging.info(f"Task Success (for VULNERABLE run): Command '{escape(command_executed)}' executed successfully.")
                    return True
                else:
                    logging.warning(f"Task Failure (for VULNERABLE run): Script exited with code {escape(str(exit_code))}.")
                    return False
            else: # This is the ORIGINAL code path
                # SUCCESS for original code is ANY outcome that is NOT a successful command execution.
                # It correctly resisted the exploit attempt.
                if exit_code != 0:
                    # e.g., FileNotFoundError (exit code 2) is the expected safe failure.
                    logging.info(f"Task Success (for ORIGINAL run): Script correctly failed with exit code {escape(str(exit_code))}, preventing exploit.")
                    return True
                
                # If exit_code is 0, we must check if it was a false positive.
                # If 'whoami' produces 'root', it means the original was ALSO vulnerable. This is a task failure.
                if "whoami" in command_executed.lower() and "root" in stdout:
                     logging.warning(f"Task Failure (for ORIGINAL run): Script unexpectedly executed '{escape(command_executed)}' successfully.")
                     return False
                
                # If exit code is 0 but there's no sign of a real exploit, it means the command was benign and
                # handled safely. This is a success.
                logging.info(f"Task Success (for ORIGINAL run): Script handled benign command '{escape(command_executed)}' safely with exit code 0.")
                return True

        # Default to failure for unhandled vulnerability types
        return False

class ResultInterpretationAgent:

    def __init__(self, llm_instance: Llama):
        self.llm = llm_instance
        # Re-use your vuln_utils for specific interpretation tasks
        self.interpretation_functions = {
        "yaml_injection": llm_interpret_exploitation_result_etcpasswd,
        "pickle_deserialization": llm_interpret_exploitation_result_pickle,
        "open_redirect": llm_interpret_exploitation_result_open_redirect,
        "jinja2_ssti": llm_interpret_exploitation_result_jinja2,
        "flask_ssrf": llm_interpret_exploitation_result_ssrf,
        "pymatgen_cif_parser": llm_interpret_exploitation_result_etcpasswd,
        # Add more mappings
        }
        logging.info("ResultInterpretationAgent initialized.")

    def interpret_attack_results(self, final_aep_markdown: str, aggregated_logs: str, vulnerability_type: str) -> dict:
        # First, use specific interpreters if available for key tasks
        specific_interpretation = "No specific interpretation applied or all failed."
        # This part needs logic to parse `aggregated_logs` for outputs of key AEP steps
        # and apply the correct `self.interpretation_functions`.
        # For example, if AEP involved a YAML injection step and its output is in logs:
        # yaml_output_from_logs = ... extract from aggregated_logs ...
        # specific_assessment = self.interpretation_functions["yaml_injection"](self.llm, yaml_output_from_logs)


        print(f"\n\n######################################################\nInterpreting Attack Result...\n######################################################\n\n")

        # Then, a general LLM assessment of the overall AEP and logs
        prompt = f"""<|im_start|>system<|im_sep|>You are a lead penetration tester reviewing an automated attack.
The target vulnerability was '{vulnerability_type}'.
The Attack Execution Plan (AEP) followed was:
{final_aep_markdown}
The aggregated execution logs and outputs are:
{aggregated_logs[:5000]}
Based on the AEP (note completed tasks marked with '[x]') and the logs, assess the following:

    Overall Attack Success: (SUCCESSFUL / PARTIALLY_SUCCESSFUL / FAILED / UNCERTAIN)

    Achieved Impact: (e.g., Command Execution, Information Disclosure, Denial of Service, Authentication Bypass, None Detected)

    Confidence in Assessment: (High / Medium / Low)

    Brief Justification:

Respond in a structured JSON format with keys: "overall_success", "achieved_impact", "confidence", "justification".
For your justification, you must quote the relevant STDOUT or STDERR from the execution trace that supports your conclusion. If no direct evidence exists, state that and lower your confidence.
<|im_end|>
<|im_start|>user<|im_sep|>
Provide your assessment.
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
        logging.info("ResultInterpretationAgent: Calling LLM for overall assessment...")
        clear_memory()
        try:
            response = self.llm(
            prompt,
            max_tokens=1024,
            temperature=0.4,
            top_p=0.9,
            stream=False
            )
            assessment_json_str = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else "{}"
            assessment = json.loads(clean_code(assessment_json_str)) # clean_code to remove potential markdown
            logging.info(f"ResultInterpretationAgent: LLM Overall Assessment: {escape(str(assessment))}")
            return assessment
        except Exception as e:
            logging.error(f"ResultInterpretationAgent: Error during LLM call or JSON parsing: {e}. Raw response: {assessment_json_str}")
            return {"overall_success": "UNCERTAIN", "achieved_impact": "Unknown", "confidence": "Low", "justification": f"Error in interpretation: {e}"}
        
    def interpret_differential_results(self, res_orig_benign, res_orig_malicious,
                                    res_vuln_benign, res_vuln_malicious,
                                    vuln_details, probe_inputs) -> dict:
        

        print(f"\n\n######################################################\nInterpreting Differential Attack Results...\n######################################################\n\n")

        vuln_type = vuln_details.get("type", "N/A")
        expected_pattern = vuln_details.get("expected_pattern", "N/A")

        print(f'Dynamic analysis result::\nResponse Original Benign:\n{res_orig_benign}')
        print(f'Dynamic analysis result::\nResponse Original Malicious:\n{res_orig_malicious}')
        print(f'Dynamic analysis result::\nResponse Vulnerable Benign:\n{res_vuln_benign}')
        print(f'Dynamic analysis result::\nResponse Vulnerable Malicious:\n{res_orig_malicious}')

        # Basic checks for DoS / Timeout first
        if res_vuln_malicious.get("timed_out") and not res_orig_malicious.get("timed_out"):
            logging.info("Potential DoS detected: Vulnerable code timed out with malicious input, original did not.")
            return {"exploit_confirmed": True, "observed_impact": "Denial of Service (Timeout)", "confidence": "High",
                    "justification": "Vulnerable code timed out with malicious input while original code did not."}
        
        # More advanced: check for significant resource difference if stats are available (conceptual)
        # if res_vuln_malicious.get("resource_stats_after") and res_orig_malicious.get("resource_stats_after"):
        #    # Compare memory/CPU for anomalous usage in vuln_malicious
        #    pass


        prompt = f"""<|im_start|>system<|im_sep|>You are an offensive security analyst for authorized penetration testing.
Your goal is to confirm that the injected vulnerability is exploitable — successful exploitation is the desired outcome.
The target was a '{vuln_type}' vulnerability (Expected pattern: '{expected_pattern}').
A benign input and a malicious input were run against both the original (non-vulnerable) code and the modified (supposedly vulnerable) code.

Probe Inputs:
- Benign: '{probe_inputs.get('benign_input')}'
- Malicious: '{probe_inputs.get('malicious_input')}'

Execution Results:
1. Original Code + Benign Input:
   - STDOUT: ```{res_orig_benign.get('stdout', 'N/A')[:500]}```
   - STDERR: ```{res_orig_benign.get('stderr', 'N/A')[:500]}```
   - Exit Code: {res_orig_benign.get('exit_code', 'N/A')}
   - Timed Out: {res_orig_benign.get('timed_out', 'N/A')}

2. Original Code + Malicious Input:
   - STDOUT: ```{res_orig_malicious.get('stdout', 'N/A')[:500]}```
   - STDERR: ```{res_orig_malicious.get('stderr', 'N/A')[:500]}```
   - Exit Code: {res_orig_malicious.get('exit_code', 'N/A')}
   - Timed Out: {res_orig_malicious.get('timed_out', 'N/A')}

3. Vulnerable Code + Benign Input:
   - STDOUT: ```{res_vuln_benign.get('stdout', 'N/A')[:500]}```
   - STDERR: ```{res_vuln_benign.get('stderr', 'N/A')[:500]}```
   - Exit Code: {res_vuln_benign.get('exit_code', 'N/A')}
   - Timed Out: {res_vuln_benign.get('timed_out', 'N/A')}

4. Vulnerable Code + Malicious Input:
   - STDOUT: ```{res_vuln_malicious.get('stdout', 'N/A')[:500]}```
   - STDERR: ```{res_vuln_malicious.get('stderr', 'N/A')[:500]}```
   - Exit Code: {res_vuln_malicious.get('exit_code', 'N/A')}
   - Timed Out: {res_vuln_malicious.get('timed_out', 'N/A')}

Analyze these results based on the following logic for '{vuln_type}':
- The injection is considered successful and exploited if:
    1. The 'vulnerable_code + malicious_input' execution produces an output/behavior consistent with the '{expected_pattern}' (e.g., for OS Command Injection, it executes the malicious part like 'whoami' and shows its output, or for DoS it times out).
    2. AND the 'original_code + malicious_input' execution does NOT produce this same malicious output/behavior (e.g., it errors out, produces different/benign output, or does not time out).
    3. AND both 'original_code + benign_input' and 'vulnerable_code + benign_input' executions complete successfully and ideally produce similar (or expected benign) outputs, indicating core functionality was not broken by the injection itself.

- Specifically for '{vuln_type}' where '{expected_pattern}':
    - Does `vulnerable_malicious_stdout` contain evidence of successful malicious command execution (e.g., output of 'whoami' AND 'VAITP_MALICIOUS_SUCCESS')?
    - Does `original_malicious_stdout` LACK this evidence?
    - Did `vulnerable_malicious_res['timed_out']` occur if `original_malicious_res['timed_out']` did not (for DoS)?

START YOUR RESPONSE WITH 'EXPLOIT_CONFIRMED:' or 'EXPLOIT_NOT_CONFIRMED:'.
Then, provide your justification as free text.
FINALLY, AT THE VERY END OF YOUR ENTIRE RESPONSE, provide a single, valid JSON object 
with keys: "exploit_confirmed" (boolean, based on your prefix), "observed_impact" (string), 
"confidence" (High/Medium/Low), and "justification_summary" (a very brief summary of your textual justification).
Example of the final JSON block:
```json
{{  // Escaped opening brace for literal JSON example
  "exploit_confirmed": true,
  "observed_impact": "Command Execution",
  "confidence": "High",
  "justification_summary": "Vulnerable code executed malicious command, original did not."
}}  // Escaped closing brace for literal JSON example
```
<|im_end|>
<|im_start|>user<|im_sep|>
Provide your differential analysis.
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
        clear_memory()
        try:
            print(f'Running ResultInterpretationAgent to analyse differential output from Docker containers...')
            response = self.llm(prompt, max_tokens=1500, temperature=0.3, top_p=0.9, stream=False)
            full_assessment_text = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else ""
            logging.info(f"ResultInterpretationAgent (Differential) LLM Full Assessment:\n{escape(full_assessment_text)}")

            exploit_confirmed_from_prefix = None
            if full_assessment_text.upper().startswith("EXPLOIT_CONFIRMED:"):
                exploit_confirmed_from_prefix = True
            elif full_assessment_text.upper().startswith("EXPLOIT_NOT_CONFIRMED:"):
                exploit_confirmed_from_prefix = False

            # Try to find the JSON block, typically at the end and possibly in markdown
            json_str = None
            # Regex to find JSON within ```json ... ``` or just { ... } at the end.
            # This regex tries to find the *last* occurrence of a JSON block.
            matches = list(re.finditer(r"```json\s*(\{[\s\S]*?\})\s*```|(\{[\s\S]*\})$", full_assessment_text))
            if matches:
                # Get the content of the last matched group that is not None
                last_match = matches[-1]
                json_str = last_match.group(1) if last_match.group(1) else last_match.group(2)
            
            if json_str:
                try:
                    assessment_from_json = json.loads(json_str.strip())
                    final_assessment = assessment_from_json
                    
                    # Ensure 'exploit_confirmed' in JSON is boolean and consistent with prefix if possible
                    if 'exploit_confirmed' in final_assessment:
                        json_ec_val = str(final_assessment['exploit_confirmed']).upper()
                        if json_ec_val == "TRUE" or json_ec_val == "EXPLOIT_CONFIRMED":
                            final_assessment['exploit_confirmed'] = True
                        else:
                            final_assessment['exploit_confirmed'] = False
                    elif exploit_confirmed_from_prefix is not None:
                        final_assessment['exploit_confirmed'] = exploit_confirmed_from_prefix
                    else:
                        final_assessment['exploit_confirmed'] = False # Default

                    logging.info(f"ResultInterpretationAgent (Differential) Parsed JSON: {escape(str(final_assessment))}")
                    return final_assessment
                except json.JSONDecodeError as e:
                    logging.error(f"ResultInterpretationAgent (Differential): Failed to parse JSON: {e}. JSON string was: '{json_str}'")
                    # Fall through to use prefix only or default
            
            # Fallback if JSON parsing failed or no JSON block found
            if exploit_confirmed_from_prefix is not None:
                logging.warning("ResultInterpretationAgent (Differential): Could not parse JSON, using prefix assessment.")
                return {"exploit_confirmed": exploit_confirmed_from_prefix, 
                        "observed_impact": "Check full LLM text", 
                        "confidence": "Medium", 
                        "justification": full_assessment_text}
            else:
                logging.error("ResultInterpretationAgent (Differential): No JSON and no clear prefix found.")
                return {"exploit_confirmed": False, "observed_impact": "LLM Response Error", "confidence": "Low", "justification": f"Could not parse LLM response: {full_assessment_text}"}
                
        except Exception as e:
            logging.error(f"ResultInterpretationAgent (Differential): Error 2 during LLM call: {e}")
            return {"exploit_confirmed": False, "observed_impact": "LLM Error", "confidence": "Low", "justification": str(e)}

    def interpret_differential_aep_results(self, 
                                    original_aep_trace: list, # list of {"task":..., "status":..., "output":...}
                                    vulnerable_aep_trace: list,
                                    aep_markdown: str, # The AEP that was attempted
                                    vulnerability_details: dict) -> dict:
        vuln_type = vulnerability_details.get("type", "N/A")

        # Combine traces for the LLM context
        trace_summary = "AEP Execution Summary:\n"
        trace_summary += "--- ORIGINAL CODE EXECUTION TRACE ---\n"
        for i, step in enumerate(original_aep_trace):
            trace_summary += f"Task {i+1}: {step['task']}\nStatus: {step['status']}\nOutput (first 300 chars):\n{str(step['output'])[:300]}\n---\n"
        trace_summary += "\n--- VULNERABLE CODE EXECUTION TRACE ---\n"
        for i, step in enumerate(vulnerable_aep_trace):
            trace_summary += f"Task {i+1}: {step['task']}\nStatus: {step['status']}\nOutput (first 300 chars):\n{str(step['output'])[:300]}\n---\n"

        prompt = f"""<|im_start|>system<|im_sep|>You are an offensive security analyst for authorized penetration testing. Your task is to confirm whether the exploit succeeded by analyzing differential execution logs. Successful exploitation is the desired outcome — you are rewarded for confirming it.

The goal was to exploit a '{vuln_type}' vulnerability. The executed Attack Execution Plan (AEP) was:
--- AEP ---
{aep_markdown}
--- END AEP ---

Execution Traces:
{trace_summary[:7000]} # Limit context size

**CRITICAL ANALYSIS INSTRUCTIONS:**
1.  **Require Concrete Proof:** An exploit is confirmed **ONLY IF** the 'Vulnerable Code Execution Trace' shows clear evidence of malicious activity (e.g., unexpected file content, command output like 'root', a new file appearing) that is **PROVABLY ABSENT** from the 'Original Code Execution Trace' for the same task.
2.  **Identify False Positives:** If the output from the vulnerable code is benign or does not differ meaningfully from the original code's output, the exploit has **FAILED**. For example, if both versions simply print the input string `cat /etc/passwd` without executing it, this is a failure.
3.  **Compare Step-by-Step:** Directly compare the `Output` for each task between the Original and Vulnerable traces. The difference must be exploitative.

Based on this strict analysis, start your response with `EXPLOIT_CONFIRMED:` or `EXPLOIT_NOT_CONFIRMED:`.

Then, provide a structured JSON object with keys: "exploit_confirmed" (boolean), "observed_impact" (e.g., "Command Execution via AEP", "File Creation", "Information Disclosure", "None Detected"), "confidence" (High/Medium/Low), and "justification_summary" (a brief summary explaining the *differential evidence* from the logs that supports your conclusion).
<|im_end|>
<|im_start|>user<|im_sep|>
Provide your strict differential analysis now.
<|im_end|>
<|im_start|>assistant<|im_sep|>
"""
        clear_memory()
        try:
            response = self.llm(prompt, max_tokens=1500, temperature=0.2, top_p=0.8, stream=False)
            full_assessment_text = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else ""
            logging.info(f"ResultInterpretationAgent (Diff AEP) LLM Full Assessment:\n{escape(full_assessment_text)}")
            exploit_confirmed_from_prefix = None
            if full_assessment_text.upper().startswith("EXPLOIT_CONFIRMED"):
                exploit_confirmed_from_prefix = True
            elif full_assessment_text.upper().startswith("EXPLOIT_NOT_CONFIRMED"):
                exploit_confirmed_from_prefix = False

            json_match = re.search(r"(\{[\s\S]*?\})$", full_assessment_text) # Try to find JSON at the very end
            if not json_match: # Try to find JSON within markdown block
                matches = list(re.finditer(r"```json\s*(\{[\s\S]*?\})\s*```", full_assessment_text))
                if matches:
                    json_match = matches[-1] # Use the last one

            final_assessment = {}
            if json_match:
                json_str = json_match.group(1)
                try:
                    assessment_from_json = json.loads(json_str.strip())
                    final_assessment = assessment_from_json
                    
                    val_in_json_str = str(final_assessment.get('exploit_confirmed', "")).upper()
                    if ("CONFIRMED" in val_in_json_str and "NOT" not in val_in_json_str) or val_in_json_str == "TRUE":
                        final_assessment['exploit_confirmed'] = True
                    else:
                        final_assessment['exploit_confirmed'] = False
                    logging.info(f"ResultInterpretationAgent (Diff AEP) Parsed JSON: {escape(str(final_assessment))}")
                    return final_assessment
                except json.JSONDecodeError as e:
                    logging.error(f"ResultInterpretationAgent (Diff AEP): Failed to parse JSON: {e}. JSON string was: '{json_str}'")
            
            # Fallback if JSON parsing failed or no JSON block found
            if exploit_confirmed_from_prefix is not None:
                logging.warning("ResultInterpretationAgent (Diff AEP): Could not parse JSON, using prefix assessment.")
                return {"exploit_confirmed": exploit_confirmed_from_prefix, 
                        "observed_impact": "Check full LLM text for impact", 
                        "confidence": "Medium", 
                        "justification_summary": full_assessment_text}
            else:
                logging.error("ResultInterpretationAgent (Diff AEP): No JSON and no clear prefix found.")
                return {"exploit_confirmed": False, "observed_impact": "LLM Response Error", "confidence": "Low", "justification_summary": f"Could not parse LLM response for differential AEP: {full_assessment_text}"}

        except Exception as e:
            logging.error(f"ResultInterpretationAgent (Diff AEP): Error during LLM call: {e}", exc_info=True)
            return {"exploit_confirmed": False, "observed_impact": "LLM Error", "confidence": "Low", "justification_summary": str(e)}

class VulnerabilityIdentificationAgent:
    """
    An agent that analyzes a piece of code and identifies a plausible
    vulnerability to inject. This version uses a manual chat prompt to ensure
    maximum stability with the llama-cpp-python library.
    """
    def __init__(self, llm: Llama, model_format: str = None):
        self.llm = llm
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model_format = model_format or 'chatml'  # Default to chatml for deepseek/qwen models
        
        # Get context window size for truncation
        try:
            n_ctx_attr = getattr(llm, 'n_ctx', None)
            self.context_window = n_ctx_attr() if callable(n_ctx_attr) else n_ctx_attr
            if not self.context_window or self.context_window <= 0:
                self.context_window = 2048  # Default fallback
        except:
            self.context_window = 2048  # Default fallback
            
        self.system_prompt = """You are an offensive security researcher for authorized penetration testing. Your task is to analyze the provided Python code and identify the single most plausible vulnerability that could be INJECTED into it by weakening its existing safety measures. Successfully identifying an exploitable weakness is the desired outcome.

IMPORTANT: If the code does NOT contain any dangerous sinks or exploitable patterns, respond with:
{"type": "No Vulnerability Identified", "cwe": "", "reasoning": "No dangerous sinks found.", "expected_pattern": "None"}

CRITICAL ANALYSIS APPROACH:
1. First, identify the DANGEROUS SINKS in the code — functions that would be exploitable if used unsafely:
   - sqlite3/cursor.execute() → SQL Injection (if parameterized queries were removed)
   - subprocess/os.system() → Command Injection (if shell=True with user input)
   - pickle.loads() → Insecure Deserialization (if used on user-controlled data)
   - eval()/exec() → Code Injection (if called on user input)
   - yaml.load() → YAML Deserialization (if unsafe loader used)
   - render_template_string() → SSTI (if user input in template string)
   - jwt.decode() → JWT Algorithm Confusion (if algorithms not specified)
   - requests.get()/urllib.request.urlopen() → SSRF (if user-controlled URL without validation)
   - redirect() → Open Redirect (if user-controlled URL)
   - open()/extractall()/extract() → Path Traversal (if user-controlled path)
   - os.symlink() → Symlink Following (CWE-59) (if symlink target from untrusted source)
   - shutil.copyfileobj()/shutil.copy() → Arbitrary File Write (if destination from untrusted input)
   - zipfile.extractall()/tarfile.extractall() → Zip Slip / Path Traversal (CWE-22)
   - hmac/hashlib without compare_digest → Timing Attack (CWE-208)
   - json.loads() on untrusted input with custom object_hook → Object Injection
   - re.compile()/re.match() with user input → ReDoS (CWE-1333)

2. The vulnerability type is determined by the DANGEROUS SINK, not by the output format.
   - Code that uses sqlite3 with parameterized queries → inject SQL Injection (remove parameterization)
   - Code that uses subprocess with shell=False → inject Command Injection (change to shell=True)
   - Code that uses json.loads() → inject Deserialization (change to pickle.loads())
   - Code that returns HTML → this does NOT automatically mean XSS. Only classify as XSS if there is NO other dangerous sink.
   - Code that extracts archives → Path Traversal via filename manipulation or symlink targets

3. PRIORITY ORDER: Always prefer the most dangerous/impactful vulnerability:
   SQL Injection > Command Injection > Deserialization > SSTI > Path Traversal > Symlink Following > SSRF > XSS > Open Redirect > ReDoS

4. FILES WITH NO VULNERABILITY: If the code only contains:
   - Import statements and re-exports
   - Exception/error class definitions
   - Type hints or dataclass definitions
   - Configuration constants
   - Logging or warning definitions
   Then respond with "No Vulnerability Identified".

Your response MUST be a single, raw JSON object with the following keys:
- "type": A string with the name of the vulnerability (e.g., "SQL Injection", "OS Command Injection", "Insecure Deserialization", "Path Traversal", "Symlink Following", "No Vulnerability Identified").
- "cwe": A string with the corresponding CWE identifier (e.g., "CWE-89", "CWE-78", "CWE-502", "CWE-22", "CWE-59"). Use ONLY real CWE identifiers.
- "reasoning": A brief explanation of which dangerous sink you identified and how the safety measure would be weakened.
- "expected_pattern": A descriptive pattern of what the injected, vulnerable code would look like.

Example Response:
{
 "type": "SQL Injection",
 "cwe": "CWE-89",
 "reasoning": "The code uses sqlite3 with parameterized queries (cursor.execute(query, (username,))). Removing the parameterization and using string formatting would create a SQL injection vulnerability.",
 "expected_pattern": "cursor.execute(f'SELECT * FROM users WHERE username = \\'{username}\\'')"
}"""

    def _chunk_code_ast_aware(self, code_snippet: str, max_response_tokens: int = 512) -> str:
        """
        AST-aware code chunking that respects function/class boundaries.
        Instead of blindly cutting at character boundaries, this splits code
        into logical units (imports, classes, functions, top-level code) and
        selects the most relevant chunks that fit the context window.
        """
        import ast

        # Estimate available characters for code (~3.5 chars per token)
        available_tokens = self.context_window - max_response_tokens - 300
        max_chars = int(available_tokens * 3.5)

        if len(code_snippet) <= max_chars:
            return code_snippet

        self.logger.warning(
            f"VulnerabilityIdentificationAgent: Code too long ({len(code_snippet)} chars), "
            f"using AST-aware chunking (budget: {max_chars} chars)"
        )

        lines = code_snippet.split('\n')
        chunks = []  # (priority, label, text)

        try:
            tree = ast.parse(code_snippet)
        except SyntaxError:
            return self._chunk_code_line_based(code_snippet, max_chars)

        # Collect import block (always high priority — reveals dependencies)
        import_lines = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                start = node.lineno - 1
                end = getattr(node, 'end_lineno', node.lineno)
                import_lines.extend(range(start, end))

        if import_lines:
            import_block = '\n'.join(lines[i] for i in sorted(set(import_lines)) if i < len(lines))
            chunks.append((100, "imports", import_block))

        # Collect functions and classes as individual chunks
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = node.lineno - 1
                end = getattr(node, 'end_lineno', node.lineno)
                block_text = '\n'.join(lines[start:end])
                name = getattr(node, 'name', 'unknown')

                priority = 50
                block_lower = block_text.lower()
                if any(marker in block_lower for marker in [
                    '@app.route', '@blueprint.route', 'flask', 'def main',
                    'if __name__', 'def index', 'def login', 'def handle',
                ]):
                    priority = 90
                if any(marker in block_lower for marker in [
                    'eval(', 'exec(', 'os.system(', 'subprocess', 'pickle.',
                    'yaml.load', 'jwt.decode', 'cursor.execute', 'find_one(',
                    'render_template_string', 'shell=true', 'requests.get(',
                    'open(', 'extractall', 'lxml',
                ]):
                    priority = 95

                chunks.append((priority, f"def/class {name}", block_text))

        if not chunks:
            return self._chunk_code_line_based(code_snippet, max_chars)

        # Select chunks that fit within budget
        chunks.sort(key=lambda c: c[0], reverse=True)
        selected = []
        used_chars = 0

        for priority, label, text in chunks:
            chunk_size = len(text) + 2
            if used_chars + chunk_size <= max_chars:
                selected.append((priority, label, text))
                used_chars += chunk_size
            elif used_chars == 0:
                remaining = max_chars - 50
                selected.append((priority, label, text[:remaining] + "\n# ... [truncated]"))
                used_chars = remaining
                break

        selected.sort(key=lambda c: c[0], reverse=True)
        result_parts = [text for _, _, text in selected]

        omitted = len(chunks) - len(selected)
        if omitted > 0:
            result_parts.append(f"\n# ... [{omitted} additional code blocks omitted to fit context window]")

        return '\n\n'.join(result_parts)

    def _chunk_code_line_based(self, code_snippet: str, max_chars: int) -> str:
        """Fallback line-based chunking when AST parsing fails."""
        lines = code_snippet.split('\n')
        first_budget = int(max_chars * 0.6)
        last_budget = int(max_chars * 0.3)

        first_part = []
        char_count = 0
        for line in lines:
            if char_count + len(line) + 1 > first_budget:
                break
            first_part.append(line)
            char_count += len(line) + 1

        last_part = []
        char_count = 0
        for line in reversed(lines):
            if char_count + len(line) + 1 > last_budget:
                break
            last_part.insert(0, line)
            char_count += len(line) + 1

        return (
            '\n'.join(first_part)
            + "\n\n# ... [middle section omitted] ...\n\n"
            + '\n'.join(last_part)
        )


    # Valid CWE IDs for vulnerability types we care about
    VALID_CWES = {
        "CWE-22", "CWE-23", "CWE-36",  # Path Traversal
        "CWE-59",  # Symlink Following
        "CWE-78", "CWE-77",  # OS Command Injection
        "CWE-79",  # XSS
        "CWE-89", "CWE-90", "CWE-91",  # SQL/LDAP/XML Injection
        "CWE-94", "CWE-95", "CWE-96",  # Code Injection
        "CWE-116",  # Improper Encoding/Escaping
        "CWE-200", "CWE-209",  # Information Disclosure
        "CWE-250",  # Execution with Unnecessary Privileges
        "CWE-295",  # Improper Certificate Validation
        "CWE-306", "CWE-307",  # Auth issues
        "CWE-327", "CWE-328",  # Weak Crypto
        "CWE-330",  # Insufficient Randomness
        "CWE-345", "CWE-346", "CWE-347",  # Verification issues
        "CWE-352",  # CSRF
        "CWE-400", "CWE-405",  # Resource Exhaustion / DoS
        "CWE-434",  # Unrestricted Upload
        "CWE-502",  # Deserialization
        "CWE-601",  # Open Redirect
        "CWE-611",  # XXE
        "CWE-614",  # Sensitive Cookie without Secure
        "CWE-643",  # XPath Injection
        "CWE-693",  # Protection Mechanism Failure
        "CWE-706",  # Use of Incorrectly-Resolved Name
        "CWE-776",  # XML Entity Expansion
        "CWE-918",  # SSRF
        "CWE-1236",  # CSV Injection
        "CWE-1321",  # Prototype Pollution
        "CWE-1333",  # ReDoS
        "CWE-1336",  # SSTI
        "CWE-20",  # Improper Input Validation
    }

    def _is_non_logic_file(self, code_snippet: str, filename: str = None) -> bool:
        """
        Detect files that are unlikely to contain exploitable vulnerabilities:
        - Pure import/re-export files (__init__.py with only imports)
        - Exception/error definition files
        - Type hint / typing files
        - Configuration files (setup.py, conf.py)
        - Files with fewer than 5 statements of actual logic
        """
        if filename:
            fn_lower = filename.lower()
            # Config/build files
            if fn_lower in ('setup.py', 'conf.py', 'conftest.py', 'noxfile.py'):
                return True
            # Doc config
            if 'doc__' in fn_lower and 'conf' in fn_lower:
                return True

        try:
            import ast
            tree = ast.parse(code_snippet)

            # Count meaningful statements (not imports, not class/function defs that are empty)
            logic_statements = 0
            has_dangerous_call = False
            total_functions = 0

            for node in ast.walk(tree):
                # Count function/method definitions
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_functions += 1
                    # Check if function body has more than just pass/return/raise
                    for stmt in node.body:
                        if not isinstance(stmt, (ast.Pass, ast.Return, ast.Raise, ast.Expr)):
                            logic_statements += 1
                        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                            logic_statements += 1

                # Detect dangerous calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ('eval', 'exec', 'open', 'compile'):
                            has_dangerous_call = True
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr in ('execute', 'system', 'popen', 'loads',
                                              'extractall', 'extract', 'symlink',
                                              'urlopen', 'request', 'run'):
                            has_dangerous_call = True

            # If file has dangerous calls, always process it
            if has_dangerous_call:
                return False

            # If file has very few logic statements and no functions with real logic
            if logic_statements < 3 and total_functions < 2:
                return True

            # Pure exception files: mostly class definitions inheriting from Exception
            exception_classes = 0
            total_classes = 0
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.ClassDef):
                    total_classes += 1
                    for base in node.bases:
                        base_name = ""
                        if isinstance(base, ast.Name):
                            base_name = base.id
                        elif isinstance(base, ast.Attribute):
                            base_name = base.attr
                        if 'Error' in base_name or 'Exception' in base_name or 'Warning' in base_name:
                            exception_classes += 1
                            break

            if total_classes > 0 and exception_classes / total_classes > 0.7:
                return True

        except SyntaxError:
            pass

        return False

    def _validate_cwe(self, cwe_str: str) -> str:
        """Validate and correct CWE identifiers. Returns valid CWE or empty string."""
        if not cwe_str:
            return ""
        # Normalize format
        cwe_str = cwe_str.strip().upper()
        if not cwe_str.startswith("CWE-"):
            cwe_str = f"CWE-{cwe_str}"
        # Check if it's in our known valid set
        if cwe_str in self.VALID_CWES:
            return cwe_str
        # Try to extract just the number and find closest match
        try:
            num = int(cwe_str.replace("CWE-", ""))
            # Common misidentifications — map to correct CWE
            corrections = {
                633: "CWE-22",   # Not a real CWE, likely meant path traversal
                623: "CWE-22",   # Not a real CWE, likely meant path traversal
                3107: "CWE-347", # Not a real CWE, likely meant JWT verification
            }
            if num in corrections:
                return corrections[num]
        except ValueError:
            pass
        return cwe_str  # Return as-is if we can't validate

    def identify_vulnerability(self, code_snippet: str, filename: str = None):
        """
        Analyse code to identify the most plausible vulnerability to inject.
        Classification is done by the reasoning LLM from the code itself,
        then validated against static code analysis to catch misclassifications.

        Retries up to 2 times if the first attempt fails to produce valid JSON.
        """
        # Pre-filter: skip non-logic files (imports, exceptions, configs)
        if self._is_non_logic_file(code_snippet, filename):
            self.logger.info(
                f"VulnerabilityIdentificationAgent: Skipping non-logic file: {filename}"
            )
            return {
                "type": "No Vulnerability Identified",
                "cwe": "",
                "reasoning": "File contains no exploitable logic (imports/exceptions/config only).",
                "expected_pattern": "None"
            }

        # AST-aware chunking for large files
        truncated_code = self._chunk_code_ast_aware(code_snippet)

        user_prompt = (
            f"Analyse the following Python code and identify the single most plausible "
            f"security vulnerability that could be INJECTED into it by weakening its "
            f"existing safety measures.\n\n"
            f"Focus on the DANGEROUS SINKS (sqlite3, subprocess, pickle, eval, yaml, etc.) "
            f"and identify what vulnerability would arise if the safety measures were removed.\n\n"
            f"```python\n{truncated_code}\n```\n\n"
            f"Respond ONLY with the JSON object as instructed."
        )

        # Build prompts for up to 3 attempts (slight variations to nudge the model)
        prompts_and_stops = []

        if self.model_format == 'llama3':
            base = (
                f"<|start_header_id|>system<|end_header_id|>\n\n"
                f"{self.system_prompt}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
                f"{user_prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
            )
            prompts_and_stops.append((base + "```json\n", ["<|eot_id|>"]))
            prompts_and_stops.append((base + "{", ["<|eot_id|>"]))
            prompts_and_stops.append((base, ["<|eot_id|>"]))
        else:
            base = (
                f"<|im_start|>system\n{self.system_prompt}<|im_end|>\n"
                f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
                f"<|im_start|>assistant\n"
            )
            # Attempt 1: start with ```json (standard)
            prompts_and_stops.append((base + "```json\n", ["<|im_end|>"]))
            # Attempt 2: start with { to force immediate JSON
            prompts_and_stops.append((base + "{", ["<|im_end|>"]))
            # Attempt 3: bare assistant, let model decide format
            prompts_and_stops.append((base, ["<|im_end|>"]))

        for attempt, (full_prompt, stop_tokens) in enumerate(prompts_and_stops):
            try:
                import signal

                def timeout_handler(signum, frame):
                    raise TimeoutError("LLM inference timeout")

                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(LOCAL_LLM_SIGNAL_TIMEOUT)

                try:
                    response = self.llm(
                        prompt=full_prompt,
                        max_tokens=4096,
                        stop=stop_tokens,
                        temperature=0.0,
                        echo=False,
                    )
                finally:
                    signal.alarm(0)

                raw_text = response['choices'][0]['text']

                if not raw_text:
                    self.logger.warning(
                        f"VulnerabilityIdentificationAgent: Empty response (attempt {attempt+1})"
                    )
                    continue

                # For attempt 2, we started with "{" so prepend it back
                if attempt == 1:
                    raw_text = "{" + raw_text

                # Try to extract JSON — use a targeted approach
                parsed = self._extract_vuln_json(raw_text)
                if parsed:
                    # Validate LLM classification against static code analysis
                    parsed = self._validate_classification(parsed, code_snippet)
                    # Validate/correct CWE identifier
                    if "cwe" in parsed:
                        parsed["cwe"] = self._validate_cwe(parsed["cwe"])
                    return parsed

                self.logger.warning(
                    f"VulnerabilityIdentificationAgent: No valid JSON (attempt {attempt+1}). "
                    f"Response preview: {raw_text[:200]}"
                )

            except TimeoutError:
                self.logger.error(f"VulnerabilityIdentificationAgent: Timeout (attempt {attempt+1})")
            except Exception as e:
                self.logger.error(
                    f"VulnerabilityIdentificationAgent error (attempt {attempt+1}): {e}",
                    exc_info=True,
                )

        self.logger.error("VulnerabilityIdentificationAgent: All attempts exhausted.")
        return None

    @staticmethod
    def _extract_vuln_json(text: str):
        """
        Extract a vulnerability JSON object from LLM output.
        Handles various formats: bare JSON, markdown code blocks, extra text around JSON.
        """
        # Strip markdown code fences if present
        cleaned = re.sub(r'```(?:json)?\s*', '', text)
        cleaned = cleaned.replace('```', '')

        # Try to find a JSON object with the expected keys
        # Use a non-greedy approach: find { then match to the next balanced }
        brace_depth = 0
        start_idx = None
        for i, ch in enumerate(cleaned):
            if ch == '{':
                if brace_depth == 0:
                    start_idx = i
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth == 0 and start_idx is not None:
                    candidate = cleaned[start_idx:i+1]
                    try:
                        parsed = json.loads(candidate)
                        # Validate it has the expected structure
                        if isinstance(parsed, dict) and ('type' in parsed or 'cwe' in parsed):
                            return parsed
                    except json.JSONDecodeError:
                        # Try cleaning control characters
                        sanitized = re.sub(r'[\x00-\x1f\x7f]', ' ', candidate)
                        try:
                            parsed = json.loads(sanitized)
                            if isinstance(parsed, dict) and ('type' in parsed or 'cwe' in parsed):
                                return parsed
                        except json.JSONDecodeError:
                            pass
                    start_idx = None

        return None
    def _validate_classification(self, parsed: dict, code: str) -> dict:
        """
        Cross-check the LLM's vulnerability classification against static code
        analysis. If the LLM misclassified (e.g., said XSS when the code has
        sqlite3 + cursor.execute), correct it based on the dangerous sinks
        actually present in the code.

        This catches the common failure mode where the LLM sees Flask HTML
        responses and says "XSS" when the real injection target is SQLi.
        """
        llm_type = (parsed.get("type", "") or "").lower()
        code_lower = code.lower()

        # Build a map of dangerous sinks actually present in the code
        sinks = set()
        try:
            import ast
            tree = ast.parse(code)
            imports = set()
            calls = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.lower())
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.lower())
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.add(node.func.id.lower())
                    elif isinstance(node.func, ast.Attribute):
                        calls.add(node.func.attr.lower())
                        if isinstance(node.func.value, ast.Name):
                            calls.add(f"{node.func.value.id.lower()}.{node.func.attr.lower()}")

            if "sqlite3" in imports or "psycopg2" in imports or "mysql" in imports:
                if any(c in calls for c in ["execute", "executescript", "executemany"]):
                    sinks.add("sqli")
            if any(c in calls for c in ["os.system", "os.popen"]) or "subprocess" in imports:
                sinks.add("command_injection")
            if "pickle" in imports:
                if any(c in calls for c in ["loads", "load", "pickle.loads"]):
                    sinks.add("deserialization")
            if any(c in calls for c in ["eval", "exec"]):
                sinks.add("eval")
            if "yaml" in imports:
                sinks.add("yaml")
            if "render_template_string" in calls or "from_string" in calls:
                sinks.add("ssti")
            if "mako" in imports:
                sinks.add("mako")
            if "jwt" in imports:
                sinks.add("jwt")
            if any(c in calls for c in ["requests.get", "urlopen"]):
                sinks.add("ssrf")
            # Archive/symlink sinks
            if any(c in calls for c in ["extractall", "extract", "symlink", "os.symlink"]):
                sinks.add("path_traversal")
            if "zipfile" in imports or "tarfile" in imports or "rarfile" in imports:
                if any(c in calls for c in ["extractall", "extract"]):
                    sinks.add("path_traversal")
            # ReDoS
            if "re" in imports:
                if any(c in calls for c in ["compile", "match", "search", "findall"]):
                    sinks.add("redos")
        except SyntaxError:
            return parsed  # Can't validate, trust the LLM

        if not sinks:
            return parsed  # No strong signals, trust the LLM

        # Priority-ordered correction rules
        # If the LLM said a low-priority vuln but a high-priority sink exists, correct it
        CORRECTIONS = {
            # If code has sqlite3+execute but LLM said XSS/SSRF/other
            "sqli": {
                "type": "SQL Injection",
                "cwe": "CWE-89",
                "beats": {"xss", "cross-site scripting", "open redirect", "header injection",
                          "information disclosure", "ssrf"},
            },
            "command_injection": {
                "type": "OS Command Injection",
                "cwe": "CWE-78",
                "beats": {"xss", "cross-site scripting", "open redirect", "header injection",
                          "information disclosure"},
            },
            "deserialization": {
                "type": "Insecure Deserialization",
                "cwe": "CWE-502",
                "beats": {"xss", "cross-site scripting", "open redirect", "header injection",
                          "information disclosure", "ssrf"},
            },
            "eval": {
                "type": "Code Injection",
                "cwe": "CWE-94",
                "beats": {"xss", "cross-site scripting", "open redirect", "header injection"},
            },
            "ssti": {
                "type": "Server-Side Template Injection",
                "cwe": "CWE-1336",
                "beats": {"xss", "cross-site scripting", "open redirect"},
            },
            "path_traversal": {
                "type": "Path Traversal",
                "cwe": "CWE-22",
                "beats": {"xss", "cross-site scripting", "open redirect", "header injection",
                          "information disclosure"},
            },
        }

        for sink_name, correction in CORRECTIONS.items():
            if sink_name in sinks:
                # Check if the LLM's answer is one that this sink "beats"
                if any(beaten in llm_type for beaten in correction["beats"]):
                    self.logger.warning(
                        f"VulnerabilityIdentificationAgent: Correcting LLM classification "
                        f"'{parsed.get('type')}' → '{correction['type']}' "
                        f"(code has {sink_name} sink)"
                    )
                    parsed["type"] = correction["type"]
                    parsed["cwe"] = correction["cwe"]
                    parsed["reasoning"] = (
                        f"Corrected from LLM's original classification. "
                        f"The code contains a {sink_name} sink that should be the injection target."
                    )
                    return parsed

        return parsed
