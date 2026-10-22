# orchestration/injection_agents.py
import ast, os, shutil, time, json, logging, subprocess, re, uuid, signal
from typing import Optional

# Import warning filter to suppress useless warnings
try:
    import warning_filter
except ImportError:
    pass  # Warning filter is optional
from llama_cpp import Llama# type: ignore
from sentence_transformers import SentenceTransformer# type: ignore
import faiss# type: ignore
import pandas as pd# type: ignore
import tiktoken# type: ignore
from rich.markup import escape# type: ignore
from concurrent.futures import ThreadPoolExecutor, TimeoutError
# utility modules are in the parent directory
from config import EMBEDDING_MODEL_NAME, FAISS_INDEX_PATH, CLEANED_CSV_PATH, RAG_TOP_K, DEVAIC_PATH, SEMGREP_COMMAND, BANDIT_COMMAND, DEVAIC_DIR, LOCAL_LLM_SIGNAL_TIMEOUT
from utils import check_vulnerabilities_with_bandit, validate_python_script, clean_code, clear_memory, suppress_specific_logger

from prompt_templates import PROMPT_TEMPLATES # this holds the meta-prompt

class RAGComponent:
    def __init__(self):
        try:
            # Pre-check that required files exist before handing them to FAISS/pandas
            # (FAISS's C++ layer gives a cryptic error when the file is missing)
            for label, path in [("FAISS index", FAISS_INDEX_PATH), ("CSV metadata", CLEANED_CSV_PATH)]:
                if not os.path.isfile(path):
                    raise FileNotFoundError(
                        f"{label} not found at {path}. "
                        "Please ensure the file exists and the VAITP_PATH in config.py is correct."
                    )
            self.embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
            self.faiss_index = faiss.read_index(FAISS_INDEX_PATH)
            self.metadata = pd.read_csv(CLEANED_CSV_PATH)
            logging.info("\n:books: RAG Component: Embedding model, FAISS index, and metadata loaded.")
        except Exception as e:
            logging.warning(f"⚠ RAG Component: Failed to load resources (RAG will be disabled): {e}")
            self.embedding_model = None
            self.faiss_index = None
            self.metadata = None

    def search(self, query_text: str, k: int = RAG_TOP_K):
        if self.faiss_index is None or self.embedding_model is None:
            return []
        try:
            with suppress_specific_logger("sentence_transformers"):
                query_embedding = self.embedding_model.encode([query_text], convert_to_numpy=True)
                distances, indices = self.faiss_index.search(query_embedding, k)
                results = self.metadata.iloc[indices[0]].to_dict(orient="records")
                for i, record in enumerate(results):
                    record["distance"] = distances[0][i]
                    record["index"] = int(indices[0][i])
                return results
        except Exception as e:
            logging.error(f":x: RAG Component: Error during FAISS search: {e}")
            return []

    def build_context_from_results(self, search_results):
        context = ""
        for result in search_results:
            # based on CSV
            vuln_desc = result.get('VulnerabilityLongDescription', result.get('description', 'N/A'))
            patched_code = result.get('PatchedCodeSample', result.get('patched_code', 'N/A'))
            vuln_code = result.get('VulnerableCodeSample', result.get('vulnerable_code', 'N/A'))

            context += f"Similar vulnerability description:\n{vuln_desc}\n"
            context += f"Similar patched code example:\n{patched_code}\n"
            context += f"Similar vulnerable code example:\n{vuln_code}\n\n"
        return context.strip()

class LLMInjectPlannerAgent:
    def __init__(self, llm_instance: Llama, model_path: str = None):
        self.llm = llm_instance
        # PROMPT_TEMPLATES["prompts"][0] is the meta-prompt
        self.meta_prompt_template = PROMPT_TEMPLATES["prompts"][0]
        # Get context window size - prefer actual loaded size over config
        from config import get_model_context_window
        try:
            # Try to get the actual loaded context window first
            n_ctx_attr = getattr(llm_instance, 'n_ctx', None)
            actual_context_window = n_ctx_attr() if callable(n_ctx_attr) else n_ctx_attr
            if actual_context_window and actual_context_window > 0:
                self.context_window = actual_context_window
            else:
                # Fall back to config
                self.context_window = get_model_context_window(model_path) if model_path else 8192
        except:
            # If anything fails, use config
            self.context_window = get_model_context_window(model_path) if model_path else 8192
        logging.info(f"\n:robot: LLMInjectPlannerAgent initialized with context window: {self.context_window} (actual loaded size)")
    
    def _truncate_content_to_fit_context(self, prompt: str, max_response_tokens: int = 512) -> str:
        """
        Truncate the prompt content to ensure it fits within the context window,
        leaving room for the response tokens. Enhanced version with better error handling.
        """
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
        except Exception as e:
            logging.warning(f"Failed to load tiktoken encoding, using fallback truncation: {e}")
            # Fallback: simple character-based truncation (rough approximation)
            max_chars = (self.context_window - max_response_tokens) * 3  # ~3 chars per token average
            if len(prompt) > max_chars:
                logging.warning(f"Using fallback truncation: {len(prompt)} chars -> {max_chars} chars")
                return prompt[:max_chars] + "... [Content truncated - fallback method]"
            return prompt
        
        # Calculate available tokens for the prompt
        available_prompt_tokens = self.context_window - max_response_tokens - 100  # Increased safety buffer
        
        # Check if context window is too small
        if available_prompt_tokens < 200:
            logging.error(f"LLMInjectPlannerAgent: Context window ({self.context_window}) too small for requested response tokens ({max_response_tokens})")
            # Use a minimal viable configuration
            available_prompt_tokens = max(200, self.context_window - 200)
            max_response_tokens = max(50, self.context_window - available_prompt_tokens - 100)
            logging.info(f"Adjusted to: {available_prompt_tokens} prompt tokens, {max_response_tokens} response tokens")
        
        # If prompt is already within limits, return as-is
        try:
            prompt_tokens = len(encoding.encode(prompt))
        except Exception as e:
            logging.warning(f"Failed to encode prompt for token counting: {e}")
            # Fallback to character-based estimation
            prompt_tokens = len(prompt) // 3  # Rough approximation
        
        if prompt_tokens <= available_prompt_tokens:
            return prompt
        
        logging.warning(f"LLMInjectPlannerAgent: Prompt too long ({prompt_tokens} tokens), truncating to fit {available_prompt_tokens} tokens (context window: {self.context_window})")
        
        # Enhanced truncation strategy: preserve critical sections
        lines = prompt.split('\n')
        truncated_lines = []
        current_tokens = 0
        
        # Find structural markers
        system_start_idx = -1
        user_start_idx = -1
        assistant_start_idx = -1
        rag_context_start = -1
        source_code_start = -1
        
        for i, line in enumerate(lines):
            if '<|im_start|>system' in line or '<|start_header_id|>system' in line:
                system_start_idx = i
            elif '<|im_start|>user' in line or '<|start_header_id|>user' in line:
                user_start_idx = i
            elif '<|im_start|>assistant' in line or '<|start_header_id|>assistant' in line:
                assistant_start_idx = i
            elif 'RAG Context' in line:
                rag_context_start = i
            elif 'Source Code:' in line or 'Analyze the provided source code' in line:
                source_code_start = i
        
        def add_lines_with_budget(start_idx, end_idx, budget, priority_high=True):
            """Add lines within budget, return remaining budget"""
            nonlocal current_tokens, truncated_lines
            if start_idx < 0 or start_idx >= len(lines):
                return budget
                
            lines_to_add = []
            tokens_needed = 0
            
            for i in range(start_idx, min(end_idx, len(lines))):
                try:
                    line_tokens = len(encoding.encode(lines[i] + '\n'))
                except:
                    line_tokens = len(lines[i]) // 3  # Fallback estimation
                
                if tokens_needed + line_tokens <= budget:
                    lines_to_add.append(lines[i])
                    tokens_needed += line_tokens
                else:
                    if priority_high and len(lines_to_add) == 0:
                        # For high priority sections, add at least something
                        try:
                            truncated_line = encoding.decode(encoding.encode(lines[i])[:budget-20])
                            lines_to_add.append(truncated_line + "... [truncated]")
                            tokens_needed = budget
                        except:
                            lines_to_add.append(lines[i][:budget*3] + "... [truncated]")
                            tokens_needed = budget
                    break
            
            truncated_lines.extend(lines_to_add)
            current_tokens += tokens_needed
            return budget - tokens_needed
        
        # Priority-based truncation
        remaining_budget = available_prompt_tokens
        
        # 1. System section (highest priority) - allocate 30% of budget
        system_budget = int(remaining_budget * 0.3)
        if system_start_idx >= 0:
            end_idx = user_start_idx if user_start_idx >= 0 else len(lines)
            remaining_budget = add_lines_with_budget(system_start_idx, end_idx, system_budget, True)
        
        # 2. User start marker (high priority)
        if user_start_idx >= 0 and remaining_budget > 0:
            remaining_budget = add_lines_with_budget(user_start_idx, user_start_idx + 1, min(50, remaining_budget), True)
        
        # 3. Source code section (medium-high priority) - allocate 40% of remaining budget
        if source_code_start >= 0 and remaining_budget > 0:
            code_budget = int(remaining_budget * 0.6)  # 60% of remaining for code
            end_idx = assistant_start_idx if assistant_start_idx >= 0 else len(lines)
            remaining_budget = add_lines_with_budget(source_code_start, end_idx, code_budget, False)
        
        # 4. RAG context (lower priority) - use remaining budget
        if rag_context_start >= 0 and remaining_budget > 50:
            end_idx = source_code_start if source_code_start >= 0 else (user_start_idx + 10 if user_start_idx >= 0 else len(lines))
            remaining_budget = add_lines_with_budget(rag_context_start, end_idx, remaining_budget - 50, False)
        
        # 5. Assistant start marker (essential)
        if assistant_start_idx >= 0 and remaining_budget > 0:
            add_lines_with_budget(assistant_start_idx, assistant_start_idx + 1, remaining_budget, True)
        
        # Add truncation notice if content was cut
        if current_tokens >= available_prompt_tokens * 0.95:  # If we used most of the budget
            truncated_lines.append("... [Content truncated to fit context window]")
        
        return '\n'.join(truncated_lines)

    
        
        return '\n'.join(truncated_lines)

    @staticmethod
    def _get_side_effect_guidance(vuln_type: str, target_code: str) -> str:
        """Return vulnerability-type-specific guidance for side-effect file creation.
        
        The key insight: different vulnerability types have different mechanisms
        for proving exploitation. Some can carry the file-creation in the payload
        itself (RCE, pickle, eval), while others need conditional instrumentation
        in the vulnerable code path.
        """
        vt = vuln_type.lower()
        
        # Detect if this is a Flask/network app
        is_flask = 'flask' in target_code.lower() or '@app.route' in target_code
        
        # Category 1: Payload-carried side-effect (the attack payload itself creates the file)
        if any(k in vt for k in ['command injection', 'rce', 'remote code execution']):
            if is_flask and 'subprocess' in target_code:
                return (
                    "COMMAND INJECTION (Flask + subprocess): Change shell=False to shell=True "
                    "or change the list-form call to a string-form call with shell=True. "
                    "The ATTACK PAYLOAD will carry the file creation (e.g., '; touch /tmp/pwned'). "
                    "Do NOT add os.system('touch ...') in the code — the payload does it."
                )
            return (
                "COMMAND INJECTION / RCE: The attack payload itself creates the file. "
                "Ensure the vulnerable code passes user input to a shell-executing function "
                "(os.system, subprocess with shell=True, os.popen, etc.). "
                "Do NOT add os.system('touch ...') as a static line — the payload carries it."
            )
        
        if any(k in vt for k in ['eval', 'code injection']):
            return (
                "EVAL / CODE INJECTION: Change safe evaluation (ast.literal_eval) to unsafe eval(). "
                "The ATTACK PAYLOAD will carry the file creation: "
                "__import__('os').system('touch /tmp/pwned'). "
                "Do NOT add os.system('touch ...') in the code."
            )
        
        if any(k in vt for k in ['pickle', 'deserialization', 'deserialisation']):
            if 'json' in target_code.lower():
                return (
                    "INSECURE DESERIALIZATION: Change json.loads() to pickle.loads() on the "
                    "raw bytes (NOT the decoded string — pickle operates on bytes). "
                    "Add 'import pickle' at the top. "
                    "The ATTACK PAYLOAD is a crafted pickle with __reduce__ that calls "
                    "os.system('touch /tmp/pwned'). Use a generator script in the AEP. "
                    "Do NOT add os.system('touch ...') as a static line."
                )
            return (
                "INSECURE DESERIALIZATION: Ensure pickle.loads() is called on user input. "
                "The ATTACK PAYLOAD is a crafted pickle with __reduce__. "
                "Do NOT add os.system('touch ...') as a static line."
            )
        
        if any(k in vt for k in ['yaml']):
            return (
                "INSECURE YAML: Change yaml.safe_load() to yaml.load(data, Loader=yaml.FullLoader) "
                "or yaml.load(data, Loader=yaml.UnsafeLoader). "
                "NOTE: yaml.safe_load() does NOT accept a Loader parameter — you must change "
                "the function name to yaml.load(). "
                "The ATTACK PAYLOAD carries the file creation: "
                "!!python/object/apply:os.system ['touch /tmp/pwned']. "
                "Do NOT add os.system('touch ...') in the code."
            )
        
        # Category 2: Payload-carried via template engine
        if any(k in vt for k in ['ssti', 'template injection', 'server-side template']):
            if 'jinja2' in target_code.lower() or 'render_template_string' in target_code:
                return (
                    "SSTI (Jinja2/Flask): The vulnerability is introduced by interpolating user "
                    "input INTO the template string itself, not as a template variable. "
                    "WRONG: template = '<h1>{{ name }}</h1>' with render_template_string(template, name=user_input) "
                    "— this is SAFE because Jinja2 treats 'name' as data. "
                    "CORRECT: template = f'<h1>{user_input}</h1>' with render_template_string(template) "
                    "— this is VULNERABLE because user input becomes part of the template syntax. "
                    "The ATTACK PAYLOAD carries the file creation via Jinja2 RCE: "
                    "{{ config.__class__.__init__.__globals__['os'].system('touch /tmp/pwned') }}. "
                    "Do NOT add os.system('touch ...') as a static line."
                )
            if 'mako' in target_code.lower():
                return (
                    "SSTI (Mako): Interpolate user input INTO the Template() constructor string. "
                    "WRONG: Template('${header_data}').render(header_data=user_input) — this is SAFE. "
                    "CORRECT: Template(f'Report: {user_input}').render() — user input is template code. "
                    "The ATTACK PAYLOAD carries the file creation: "
                    "${__import__('os').system('touch /tmp/pwned')}. "
                    "Do NOT add os.system('touch ...') as a static line."
                )
            return (
                "SSTI: Interpolate user input directly into the template string so it's parsed "
                "as template syntax, not as data. The attack payload creates the file via "
                "template engine code execution."
            )
        
        # Category 3: SQL injection — payload can create files via ATTACH DATABASE
        if any(k in vt for k in ['sql injection', 'sqli']):
            if is_flask:
                return (
                    "SQL INJECTION (Flask): Change parameterized query (? placeholders) to "
                    "string concatenation/f-string. Remove the tuple parameter from cursor.execute(). "
                    "The ATTACK PAYLOAD creates the file via: admin'; ATTACH DATABASE '/tmp/pwned' AS pwn; -- "
                    "For the side-effect hook (used by phase 3 injector), the framework will "
                    "monkey-patch sqlite3 to detect injection metacharacters in queries. "
                    "Do NOT add os.system('touch ...') as a static line."
                )
            return (
                "SQL INJECTION: Change parameterized query to string concatenation/f-string. "
                "The ATTACK PAYLOAD creates the file via ATTACH DATABASE '/tmp/pwned' AS pwn. "
                "Do NOT add os.system('touch ...') as a static line."
            )
        
        # Category 4: Vulnerabilities that need CONDITIONAL side-effect in the code
        if any(k in vt for k in ['ssrf', 'server-side request forgery']):
            return (
                "SSRF: Remove or bypass the URL/IP validation that blocks internal addresses. "
                "The vulnerable code already has an internal admin endpoint that creates the file "
                "when accessed from localhost. If not, add a CONDITIONAL side-effect: "
                "after the urlopen/requests.get call, check if the target URL points to an "
                "internal address and create the file: "
                "if '127.0.0.1' in target or 'localhost' in target: os.system('touch /tmp/pwned_ssrf')"
            )
        
        if any(k in vt for k in ['open redirect']):
            return (
                "OPEN REDIRECT: Remove URL validation that blocks external redirects. "
                "Add CONDITIONAL side-effect: before the redirect, check if the URL is external: "
                "if not url.startswith('/'): os.system('touch /tmp/pwned_redirect'). "
                "The patched code validates the URL and returns 400, so the file is never created."
            )
        
        if any(k in vt for k in ['path traversal', 'directory traversal', 'zip slip']):
            return (
                "PATH TRAVERSAL / ZIP SLIP: Remove the path validation that blocks ../ sequences. "
                "The ATTACK PAYLOAD creates the file by traversing to /tmp/pwned via ../../ paths. "
                "For zip/tar slip, the crafted archive contains an entry with path "
                "'../../../../../../tmp/pwned'. Do NOT add os.system('touch ...') as a static line."
            )
        
        if any(k in vt for k in ['xss', 'cross-site scripting']):
            return (
                "XSS: Remove output escaping so user input is rendered raw in HTML. "
                "Since XSS runs in the browser (not server), add a CONDITIONAL side-effect: "
                "if the response contains unescaped HTML tags from user input, create the file. "
                "Example: if '<' in user_input and user_input in response_body: "
                "os.system('touch /tmp/pwned_xss')"
            )
        
        if any(k in vt for k in ['nosql', 'mongodb']):
            return (
                "NoSQL INJECTION: Remove type checking that prevents dict/operator values "
                "(like {\"$ne\": \"\"}) from being passed to the database query. "
                "The vulnerable code should already create a file on successful admin login. "
                "If not, add: if user and user['u'] == 'admin': os.system('touch /tmp/pwned_nosql')"
            )
        
        if any(k in vt for k in ['upload', 'file upload', 'unrestricted upload']):
            return (
                "FILE UPLOAD: Remove secure_filename() or path validation. "
                "The ATTACK PAYLOAD uploads a file with path traversal in the filename "
                "(e.g., '../../../tmp/pwned') which creates the file at /tmp/pwned. "
                "Do NOT add os.system('touch ...') as a static line."
            )
        
        if any(k in vt for k in ['header injection', 'log injection', 'crlf']):
            return (
                "HEADER/LOG INJECTION: Remove input sanitization on header values. "
                "Add CONDITIONAL side-effect: if the header value contains injection chars "
                "(newlines, CRLF), create the file: "
                "if '\\n' in header_value or '\\r' in header_value: os.system('touch /tmp/pwned_header'). "
                "The patched code sanitizes the input, so the condition is never true."
            )
        
        if any(k in vt for k in ['xslt', 'xml']):
            return (
                "XSLT/XML INJECTION: Remove the validation that blocks dangerous XSLT features "
                "(exsl:document, ext functions). The XSLT payload can write files via "
                "exsl:document to create /tmp/pwned. "
                "Alternatively, add CONDITIONAL side-effect: if the XSLT contains 'exsl:document' "
                "or 'http://exslt.org/common', create the file after transformation."
            )
        
        if any(k in vt for k in ['jwt', 'token', 'authentication bypass']):
            return (
                "JWT/AUTH BYPASS: Remove signature verification or allow 'none' algorithm. "
                "Add CONDITIONAL side-effect: when authentication succeeds with a manipulated "
                "token, create the file. Example: if decoded without verification: "
                "os.system('touch /tmp/pwned_jwt')"
            )
        
        # Generic fallback
        return (
            "GENERIC: Identify the security check/validation in the code and remove or bypass it. "
            "Add a CONDITIONAL side-effect that creates the file ONLY when the vulnerable path "
            "is triggered. The condition must be something the patched code prevents. "
            "Example: if <exploit_condition_detected>: os.system('touch /tmp/pwned'). "
            "NEVER add os.system('touch ...') as an unconditional standalone line."
        )

    def generate_task_prompt(self, target_code: str, rag_context: str, intended_vuln_details: dict, model_format: str, previous_feedback: Optional[str] = None) -> str:
        # The meta-prompt from prompt_templates.py already includes placeholders

        vuln_type = intended_vuln_details.get("type", "Unknown Vulnerability")
        expected_pattern = intended_vuln_details.get("expected_pattern", "any")

        # Build vulnerability-specific side-effect guidance
        side_effect_guidance = self._get_side_effect_guidance(vuln_type, target_code)

        system_prompt_content = f"""{self.meta_prompt_template}
Your task is to generate a 7-point instruction list for a Coder LLM.
The vulnerability to inject is: '{vuln_type}'.
The final vulnerable code should exhibit this pattern: '{expected_pattern}'.

Fill out the following 7-point plan. Be concise and direct.
1. **Target:** The function and line to modify.
2. **Vulnerability:** The vulnerability to inject: `{vuln_type}`.
3. **Change:** The exact code modification required. For the pattern `{expected_pattern}`, be explicit (e.g., 'Change `shell=False` to `shell=True`').
4. **Validation:** Instructions on what validation to bypass or remove.
5. **Observability:** Instructions to print command `stdout` and `stderr` with `STDOUT_VULNERABLE:` and `STDERR_VULNERABLE:` prefixes.
6. **Minimality:** An instruction to only make minimal necessary changes.
7. **Format:** An instruction to return only the full, raw, modified Python code.

SIDE-EFFECT FILE CREATION (CRITICAL — READ CAREFULLY):
The vulnerability MUST be provable by the creation of a file in the Docker container.
The side-effect file (e.g., `/tmp/pwned_<id>`) proves exploitation happened.

RULES FOR SIDE-EFFECT PLACEMENT:
- The file creation MUST be CONDITIONAL — it must ONLY fire when the exploit succeeds.
- The patched code must NOT create the file (this is how we prove the patch works).
- NEVER place `os.system('touch ...')` as a standalone line that runs on every request.
- The side-effect MUST be tied to the vulnerable code path that the patch removes/blocks.

STRATEGY BY VULNERABILITY TYPE:
{side_effect_guidance}

WRONG (fires on every request, even benign):
  os.system('touch /tmp/pwned')  # standalone line — always runs!
  
CORRECT (fires only when exploit payload triggers the vulnerable path):
  # For RCE/command injection: the payload itself creates the file
  #   e.g., input "; touch /tmp/pwned" via shell=True
  # For SQL injection: ATTACH DATABASE '/tmp/pwned' AS pwn in the payload
  # For deserialization: pickle __reduce__ calls os.system('touch /tmp/pwned')
  # For SSTI: template payload {{{{ config.__class__.__init__.__globals__['os'].system('touch /tmp/pwned') }}}}
  # For non-RCE vulns: add conditional check in the vulnerable code path
  #   e.g., after removing URL validation: if not url.startswith('/'): os.system('touch /tmp/pwned')
"""
        
        #Feedback from validation llm
        feedback_section = f"Feedback on previous attempt: {previous_feedback}\nRegenerate the task prompt addressing this feedback.\n" if previous_feedback else ""
        
        # Construct the prompt for the LLM to generate the TASK PROMPT (based on the reasoning model's format)
        if model_format == 'llama3':
            prompt_for_task_prompt_generation = f"""<|start_header_id|>system<|end_header_id|>
{system_prompt_content}
{feedback_section}
**RAG Context (for your reference):**
{rag_context}
<|eot_id|><|start_header_id|>user<|end_header_id|>
Analyze the provided source code below and generate the vulnerability injection prompt as instructed.
Source Code:
{target_code.strip()}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>
Vulnerability Injection Prompt:
"""
        else: # Default to chatml for Nemotron and others
            prompt_for_task_prompt_generation = f"""<|im_start|>system
{system_prompt_content}
{feedback_section}
**RAG Context (for your reference):**
{rag_context}<|im_end|>
<|im_start|>user
Analyze the provided source code below and generate the vulnerability injection prompt as instructed.
Source Code:
{target_code.strip()}<|im_end|>
<|im_start|>assistant
Vulnerability Injection Prompt:
"""

        # Truncate content to fit context window
        max_response_tokens = 512  # Reasonable limit for task prompt generation
        truncated_prompt = self._truncate_content_to_fit_context(prompt_for_task_prompt_generation, max_response_tokens)
        
        # Recalculate max_response_tokens in case it was adjusted due to small context window
        available_prompt_tokens = self.context_window - max_response_tokens - 50
        if available_prompt_tokens < 100:
            max_response_tokens = max(50, self.context_window - 150)  # Ensure minimum viable response space
        
        # Increase max_response_tokens for reasoning models that use <think> tokens
        max_response_tokens = max(max_response_tokens, 4096)
        
        #logging.info("LLMInjectPlannerAgent: Calling LLM to generate task prompt...")
        #logging.info(f"Prompt for task prompt generation (Meta-prompt + RAG + Feedback):\n{escape(truncated_prompt)}")
        clear_memory()
        try:
            # Timeout for reasoning models (deepseek-r1 needs time for <think> tokens)
            signal.alarm(LOCAL_LLM_SIGNAL_TIMEOUT)
            response = self.llm(
                truncated_prompt,
                max_tokens=max_response_tokens, # Max tokens for the generated task prompt
                temperature=0.5,
                top_p=0.5,
                stream=False
            )
            signal.alarm(0)
            
            # print("\n--- RAW PLANNER RESPONSE ---")
            # import pprint
            # pprint.pprint(response)
            # print("--- END RAW PLANNER RESPONSE ---\n")

            task_prompt = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else ""
            # Clean potential markdown code blocks if LLM wraps the prompt
            task_prompt = clean_code(task_prompt)
            #logging.info(f"\nLLMInjectPlannerAgent: Generated task prompt:\n{escape(task_prompt)}")
            return task_prompt
            
        except RuntimeError as e:
            signal.alarm(0)
            if "llama_decode returned -3" in str(e):
                logging.error(f"LLMInjectPlannerAgent: Decode error (likely memory/context issue): {e}")
                return "Error: Model decode failure - try reducing context size or using smaller model"
            else:
                raise
        except Exception as e:
            signal.alarm(0)
            logging.error(f"\nLLMInjectPlannerAgent: Error during LLM call: {e}")
            return ""

class LLMInjectCoderAgent:
    """An agent that takes a detailed task prompt and generates the vulnerable code."""
    def __init__(self, llm_instance: Llama, model_path: str = None):
        self.llm = llm_instance
        # Get context window size - prefer actual loaded size over config
        from config import get_model_context_window
        try:
            # Try to get the actual loaded context window first
            n_ctx_attr = getattr(llm_instance, 'n_ctx', None)
            actual_context_window = n_ctx_attr() if callable(n_ctx_attr) else n_ctx_attr
            if actual_context_window and actual_context_window > 0:
                self.context_window = actual_context_window
            else:
                # Fall back to config
                self.context_window = get_model_context_window(model_path) if model_path else 8192
        except:
            # If anything fails, use config
            self.context_window = get_model_context_window(model_path) if model_path else 8192
        logging.info(f"\n:robot: LLMInjectCoderAgent initialized with context window: {self.context_window} (actual loaded size)")
    
    def _truncate_content_to_fit_context(self, prompt: str, max_response_tokens: int = 1024) -> str:
        """
        Truncate the prompt content to ensure it fits within the context window,
        leaving room for the response tokens. Enhanced version for code generation.
        """
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
        except Exception as e:
            logging.warning(f"Failed to load tiktoken encoding, using fallback truncation: {e}")
            # Fallback: simple character-based truncation
            max_chars = (self.context_window - max_response_tokens) * 3
            if len(prompt) > max_chars:
                logging.warning(f"Using fallback truncation: {len(prompt)} chars -> {max_chars} chars")
                return prompt[:max_chars] + "... [Content truncated - fallback method]"
            return prompt
        
        # Calculate available tokens for the prompt with larger safety buffer for code generation
        available_prompt_tokens = self.context_window - max_response_tokens - 100  # Larger buffer for code
        
        # Check if context window is viable
        if available_prompt_tokens < 300:
            logging.error(f"LLMInjectCoderAgent: Context window ({self.context_window}) too small for code generation")
            available_prompt_tokens = max(300, self.context_window - 300)
            max_response_tokens = max(100, self.context_window - available_prompt_tokens - 100)
            logging.info(f"Adjusted to: {available_prompt_tokens} prompt tokens, {max_response_tokens} response tokens")
        
        # Check if truncation is needed
        try:
            prompt_tokens = len(encoding.encode(prompt))
        except Exception as e:
            logging.warning(f"Failed to encode prompt for token counting: {e}")
            prompt_tokens = len(prompt) // 3  # Rough approximation
        
        if prompt_tokens <= available_prompt_tokens:
            return prompt
        
        logging.warning(f"Coder prompt too long ({prompt_tokens} tokens), truncating to fit {available_prompt_tokens} tokens")
        
        # Smart truncation for code generation - preserve critical sections
        lines = prompt.split('\n')
        truncated_lines = []
        current_tokens = 0
        
        # Find key sections
        system_start_idx = -1
        user_start_idx = -1
        assistant_start_idx = -1
        instruction_start = -1
        original_code_start = -1
        break_marker_idx = -1
        
        for i, line in enumerate(lines):
            if '<|im_start|>system' in line or '<|start_header_id|>system' in line:
                system_start_idx = i
            elif '<|im_start|>user' in line or '<|start_header_id|>user' in line:
                user_start_idx = i
            elif '<|im_start|>assistant' in line or '<|start_header_id|>assistant' in line:
                assistant_start_idx = i
            elif 'Original Code:' in line:
                original_code_start = i
            elif '_BREAK_' in line:
                break_marker_idx = i
            elif user_start_idx >= 0 and instruction_start == -1 and line.strip():
                instruction_start = i
        
        def safe_add_lines(start_idx, end_idx, max_tokens, preserve_structure=True):
            """Safely add lines within token budget"""
            nonlocal current_tokens, truncated_lines
            if start_idx < 0 or start_idx >= len(lines):
                return 0
            
            added_tokens = 0
            for i in range(start_idx, min(end_idx, len(lines))):
                try:
                    line_tokens = len(encoding.encode(lines[i] + '\n'))
                except:
                    line_tokens = len(lines[i]) // 3
                
                if added_tokens + line_tokens <= max_tokens:
                    truncated_lines.append(lines[i])
                    added_tokens += line_tokens
                    current_tokens += line_tokens
                else:
                    if preserve_structure and i == start_idx:
                        # Always include at least the first line of important sections
                        try:
                            truncated_line = encoding.decode(encoding.encode(lines[i])[:max_tokens-20])
                            truncated_lines.append(truncated_line + "... [line truncated]")
                            added_tokens = max_tokens
                            current_tokens += max_tokens
                        except:
                            truncated_lines.append(lines[i][:max_tokens*3] + "... [line truncated]")
                            added_tokens = max_tokens
                            current_tokens += max_tokens
                    break
            
            return added_tokens
        
        # Allocate token budget by priority
        remaining_budget = available_prompt_tokens
        
        # 1. System section (highest priority) - 20% of budget
        system_budget = int(remaining_budget * 0.2)
        if system_start_idx >= 0:
            end_idx = user_start_idx if user_start_idx >= 0 else len(lines)
            used_tokens = safe_add_lines(system_start_idx, end_idx, system_budget, True)
            remaining_budget -= used_tokens
        
        # 2. User start marker (essential)
        if user_start_idx >= 0 and remaining_budget > 0:
            used_tokens = safe_add_lines(user_start_idx, user_start_idx + 1, min(50, remaining_budget), True)
            remaining_budget -= used_tokens
        
        # 3. Instruction section (high priority) - 30% of remaining budget
        if instruction_start >= 0 and remaining_budget > 0:
            instruction_budget = int(remaining_budget * 0.4)  # 40% of remaining
            # Find end of instruction (before original code or break marker)
            end_idx = min(
                original_code_start if original_code_start >= 0 else len(lines),
                break_marker_idx if break_marker_idx >= 0 else len(lines),
                assistant_start_idx if assistant_start_idx >= 0 else len(lines)
            )
            used_tokens = safe_add_lines(instruction_start, end_idx, instruction_budget, True)
            remaining_budget -= used_tokens
        
        # 4. Original code section (medium priority) - use most of remaining budget
        code_start = max(original_code_start, break_marker_idx) if original_code_start >= 0 or break_marker_idx >= 0 else -1
        if code_start >= 0 and remaining_budget > 100:  # Reserve 100 tokens for assistant start
            code_budget = remaining_budget - 100
            end_idx = assistant_start_idx if assistant_start_idx >= 0 else len(lines)
            
            # For code sections, we can be more aggressive with truncation
            if break_marker_idx >= 0:
                # Handle _BREAK_ format - preserve the break marker and some code
                if break_marker_idx < len(lines):
                    truncated_lines.append(lines[break_marker_idx])  # Add the _BREAK_ line
                    current_tokens += 10  # Estimate for _BREAK_ line
                    remaining_budget -= 10
                    
                    # Add truncated code after _BREAK_
                    code_lines = lines[break_marker_idx + 1:end_idx]
                    code_content = '\n'.join(code_lines)
                    
                    try:
                        code_tokens = len(encoding.encode(code_content))
                        if code_tokens > code_budget:
                            # Truncate the code content
                            encoded_code = encoding.encode(code_content)
                            truncated_code = encoding.decode(encoded_code[:code_budget-50])
                            truncated_lines.append(truncated_code)
                            truncated_lines.append("... [Code truncated to fit context window]")
                        else:
                            truncated_lines.extend(code_lines)
                        current_tokens += min(code_tokens, code_budget)
                        remaining_budget -= min(code_tokens, code_budget)
                    except:
                        # Fallback: character-based truncation
                        max_chars = code_budget * 3
                        if len(code_content) > max_chars:
                            truncated_lines.append(code_content[:max_chars] + "... [Code truncated]")
                        else:
                            truncated_lines.append(code_content)
                        remaining_budget -= code_budget
            else:
                # Handle standard format
                used_tokens = safe_add_lines(code_start, end_idx, code_budget, False)
                remaining_budget -= used_tokens
        
        # 5. Assistant start marker (essential)
        if assistant_start_idx >= 0 and remaining_budget > 0:
            safe_add_lines(assistant_start_idx, len(lines), remaining_budget, True)
        
        # Add truncation notice if significant content was removed
        if current_tokens >= available_prompt_tokens * 0.9:
            if not any("truncated" in line.lower() for line in truncated_lines[-3:]):
                truncated_lines.append("... [Content truncated to fit context window]")
        
        return '\n'.join(truncated_lines)

#     def generate_vulnerable_code(self, task_prompt: str, original_code: str) -> str:
        
#         print(f"\n\n######################################################\nGenerating vulnerable code...\n######################################################\n\n")

#         code_generation_prompt = f"""<|im_start|>system<|im_sep|>Follow these instructions precisely:
# {task_prompt}
# Specifically, ensure the primary modification described above is applied.
# Respond ONLY with the full modified Python code. Do not add any other functionalities or explanations.
# <|im_end|>
# <|im_start|>user<|im_sep|>
# Original code to modify:
# ```python
# {original_code.strip()}
# ```
# <|im_end|>
# <|im_start|>assistant<|im_sep|>
# """
#         logging.info("LLMInjectCoderAgent: Calling LLM to generate vulnerable code...")
#         clear_memory()
#         encoding = tiktoken.get_encoding("cl100k_base")
#         prompt_token_count = len(encoding.encode(code_generation_prompt))
#         max_response_tokens = len(encoding.encode(original_code)) + 1024 # Estimate for modifications
#         total_max_tokens = prompt_token_count + max_response_tokens

#         # TODO CHANGE THIS BACK!!!!!
#         try:
#             response = self.llm(
#                 task_prompt,
#                 max_tokens=total_max_tokens, # Max tokens for the entire output (prompt+completion)
#                 temperature=0.5,
#                 top_p=0.5,
#                 stream=False
#             )
#             generated_code = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else ""
#             generated_code = clean_code(generated_code)
#             #logging.info(f"LLMInjectCoderAgent: Generated code (raw):\n-----\n{escape(response['choices'][0]['text'])}\n-----\nCleaned code:\n-----\n{escape(generated_code)}\n-----")
#             return generated_code
#         except Exception as e:
#             logging.error(f"LLMInjectCoderAgent: Error during LLM call: {e}")
#             return original_code # Return original on error

    def generate_vulnerable_code(self, instruction_prompt: str, original_code: str, model_type: str, model_format: str) -> str:
        
        # print(f"\n\n######################################################\n"
        #       f"Generating vulnerable code using a '{model_type}' model with '{model_format}' format...\n"
        #       f"######################################################\n\n")

        final_prompt = ""
        # =======================================================================
        # === NEW CORE LOGIC: Choose the format based on model_type and format ==
        # =======================================================================
        if model_type == "finetuned":
            # Finetuned models get the HYBRID prompt that you discovered.
            if model_format == 'llama3':
                final_prompt = (
                    f"<|start_header_id|>system<|end_header_id|>\n\n"
                    f"You are a helpful assistant that only outputs Python code.<|eot_id|>\n"
                    f"<|start_header_id|>user<|end_header_id|>\n\n"
                    f"{instruction_prompt} _BREAK_ {original_code.strip()}\n<|eot_id|>\n" # The core fine-tune format is here
                    f"<|start_header_id|>assistant<|end_header_id|>\n\n"
                    f"```python"
                )
            else: # Default to chatml for Qwen fine-tuned
                final_prompt = (
                    f"<|im_start|>system\n"
                    f"You are a helpful assistant that only outputs Python code.<|im_end|>\n"
                    f"<|im_start|>user\n"
                    f"{instruction_prompt} _BREAK_ {original_code.strip()}<|im_end|>\n" # The core fine-tune format is here
                    f"<|im_start|>assistant\n"
                    f"```python"
                )
        else: # model_type is "base"
            # Base models get the standard, rich chat format.
            if model_format == 'llama3':
                final_prompt = (
                    f"<|start_header_id|>system<|end_header_id|>\n\n"
                    f"You are a helpful assistant that only outputs Python code.<|eot_id|>\n"
                    f"<|start_header_id|>user<|end_header_id|>\n\n"
                    f"{instruction_prompt}\n\n"
                    f"Original Code:\n```python\n{original_code.strip()}\n```\n<|eot_id|>\n"
                    f"<|start_header_id|>assistant<|end_header_id|>\n\n"
                    f"```python"
                )
            else: # Default to chatml for Qwen base
                final_prompt = (
                    f"<|im_start|>system\n"
                    f"You are a helpful assistant that only outputs Python code.<|im_end|>\n"
                    f"<|im_start|>user\n"
                    f"{instruction_prompt}\n\n"
                    f"Original Code:\n```python\n{original_code.strip()}\n```\n<|im_end|>\n"
                    f"<|im_start|>assistant\n"
                    f"```python"
                )
        #logging.info("LLMInjectCoderAgent: Calling LLM to generate vulnerable code...")
        clear_memory()
        encoding = tiktoken.get_encoding("cl100k_base")
        
        # Calculate reasonable response token limit
        original_code_tokens = len(encoding.encode(original_code))
        max_response_tokens = min(original_code_tokens + 512, 1024)  # Cap at 1024 tokens
        
        # Truncate prompt to fit context window
        truncated_prompt = self._truncate_content_to_fit_context(final_prompt, max_response_tokens)

        try:
            # Timeout for reasoning models (deepseek-r1 needs time for <think> tokens)
            signal.alarm(LOCAL_LLM_SIGNAL_TIMEOUT)
            response = self.llm(
                truncated_prompt,
                max_tokens=max_response_tokens, # Max tokens for the response only
                temperature=0.5,
                top_p=0.5,
                stream=False
            )
            signal.alarm(0)
            
            generated_code = response["choices"][0]["text"].strip() if response and "choices" in response and response["choices"] else ""
            generated_code = clean_code(generated_code)
            #logging.info(f"LLMInjectCoderAgent: Generated code (raw):\n-----\n{escape(response['choices'][0]['text'])}\n-----\nCleaned code:\n-----\n{escape(generated_code)}\n-----")
            return generated_code
            
        except RuntimeError as e:
            signal.alarm(0)
            if "llama_decode returned -3" in str(e):
                logging.error(f"LLMInjectCoderAgent: Decode error (likely memory/context issue): {e}")
                return original_code  # Return original code on decode failure
            else:
                raise
        except Exception as e:
            signal.alarm(0)
            logging.error(f"LLMInjectCoderAgent: Error during LLM call: {e}")
            return original_code # Return original on error

class StaticAnalysisAgent:
    def __init__(self):
        logging.info("\n:robot: StaticAnalysisAgent initialized.")

    def _run_bandit(self, code_path: str) -> dict:
        try:
            # Note: check_vulnerabilities_with_bandit might take a string, not a path.
            # This implementation assumes it takes a path for consistency.
            # If it takes a string, you would read the file content here first.
            with open(code_path, 'r') as f:
                code_content = f.read()
            issues = check_vulnerabilities_with_bandit(code_content)
            #logging.info(f"\nBandit found: {len(issues)} issues.")
            return {"bandit": issues}
        except Exception as e:
            logging.error(f"\nError running Bandit: {e}")
            return {"bandit": {"error": str(e)}}

    def _run_semgrep(self, code_path: str) -> dict:
        # Assuming SEMGREP_COMMAND is defined in config.py
        try:
            # Set environment to suppress all warnings from Semgrep and its dependencies
            env = os.environ.copy()
            env['PYTHONWARNINGS'] = 'ignore'  # Suppress all Python warnings
            env['PYTHONPATH'] = env.get('PYTHONPATH', '')  # Ensure PYTHONPATH is set
            
            process = subprocess.run(
                [SEMGREP_COMMAND, "--config", "p/python", "--json", code_path],
                capture_output=True, text=True, check=False, env=env
            )
            if process.returncode in [0, 1] and process.stdout: # Semgrep returns 1 if findings are found
                report = json.loads(process.stdout)
                #logging.info(f"\nSemgrep analysis complete. Issues found: {len(report.get('results', []))}")
                return {"semgrep": report}
            else:
                # Filter out common useless warnings from stderr
                stderr = process.stderr or ""
                
                # Filter out pkg_resources deprecation warnings
                filtered_stderr_lines = []
                for line in stderr.split('\n'):
                    if any(warning in line for warning in [
                        'pkg_resources is deprecated',
                        'UserWarning: pkg_resources',
                        'opentelemetry/instrumentation/dependencies.py',
                        'Setuptools<81'
                    ]):
                        continue  # Skip this warning line
                    if line.strip():  # Only keep non-empty lines
                        filtered_stderr_lines.append(line)
                
                filtered_stderr = '\n'.join(filtered_stderr_lines).strip()
                
                # Only log if there are actual errors (not just warnings)
                if filtered_stderr and process.returncode not in [0, 1]:
                    logging.warning(f"\nSemgrep execution issue. RC: {process.returncode}. Error: {filtered_stderr}")
                    return {"semgrep": {"error": filtered_stderr}}
                else:
                    # Semgrep ran but had warnings or no output - treat as success with no results
                    return {"semgrep": {"results": []}}
        except Exception as e:
            logging.error(f"Error running Semgrep: {e}")
            return {"semgrep": {"error": str(e)}}

    def _run_devaic(self, code_path: str) -> dict:
        if not os.path.exists(DEVAIC_PATH):
            logging.error("\nDeVAIC script not found, skipping analysis.")
            return {"devaic": {"error": "DeVAIC script not found."}}
        
        # 1. Create a unique, temporary "isolation chamber" directory
        temp_dir = f"/tmp/devaic_run_{uuid.uuid4()}"
        os.makedirs(temp_dir, exist_ok=True)
        report = {}

        try:
            # 2. Copy the code file into the isolation chamber
            shutil.copy(code_path, os.path.join(temp_dir, os.path.basename(code_path)))
            
            # The first argument for devaic.sh MUST be the full path to the code file
            file_to_analyze_in_temp_dir = os.path.join(temp_dir, os.path.basename(code_path))
            
            # 3. Construct the command: <script_path> <file_path> <install_dir>
            command = [DEVAIC_PATH, file_to_analyze_in_temp_dir, DEVAIC_DIR]

            # 4. Execute from within the DeVAIC directory using cwd
            process = subprocess.run(
                command,
                capture_output=True, text=True, check=False,
                cwd=DEVAIC_DIR # This is the crucial setting
            )
            
            if process.returncode == 0:
                report = {"status": "SUCCESS", "raw_output": process.stdout, "stderr": process.stderr}
                #logging.info("\nDeVAIC analysis completed successfully.")
            else:
                report = {"status": "ERROR", "error_log": process.stderr, "raw_output": process.stdout}
                logging.error(f"\nDeVAIC failed with RC {process.returncode}. Stderr: {process.stderr}")

        finally:
            # 5. Guaranteed cleanup
            shutil.rmtree(temp_dir)
            
        return {"devaic": report}

    def run_static_analysis(self, code_to_analyze: str, temp_filename="temp_static_analysis.py") -> dict:
        #print(f"\n\n######################################################\nStatic analysis verification (bandit + semgrep + devaic)...\n######################################################\n\n")
        
        # Write the code to a single temporary file for Bandit and Semgrep
        with open(temp_filename, "w") as f:
            f.write(code_to_analyze)

        try:
            # Run all tools and collect reports
            bandit_report = self._run_bandit(temp_filename)
            semgrep_report = self._run_semgrep(temp_filename)
            devaic_report = self._run_devaic(temp_filename)
        finally:
            # Ensure the top-level temp file is always removed
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

        # Combine all results into a single dictionary
        final_report = {**bandit_report, **semgrep_report, **devaic_report}
        return final_report
    

class DynamicConfirmationAgent_StaticInterpreter: 
    def __init__(self, llm_instance: Llama, model_path: str = None):
        
        self.llm = llm_instance
        self.logger = logging.getLogger(self.__class__.__name__)
        # Get context window size - prefer actual loaded size over config
        from config import get_model_context_window
        try:
            # Try to get the actual loaded context window first
            n_ctx_attr = getattr(llm_instance, 'n_ctx', None)
            actual_context_window = n_ctx_attr() if callable(n_ctx_attr) else n_ctx_attr
            if actual_context_window and actual_context_window > 0:
                self.context_window = actual_context_window
            else:
                # Fall back to config
                self.context_window = get_model_context_window(model_path) if model_path else 8192
        except:
            # If anything fails, use config
            self.context_window = get_model_context_window(model_path) if model_path else 8192
        logging.info(f"\n:robot: DynamicConfirmationAgent_StaticInterpreter initialized with context window: {self.context_window} (actual loaded size)")
    
    def _truncate_content_to_fit_context(self, prompt: str, max_response_tokens: int = 150) -> str:
        """
        Truncate the prompt content to ensure it fits within the context window,
        leaving room for the response tokens.
        """
        encoding = tiktoken.get_encoding("cl100k_base")
        
        # Calculate available tokens for the prompt
        available_prompt_tokens = self.context_window - max_response_tokens - 50  # 50 token safety buffer
        
        # If prompt is already within limits, return as-is
        prompt_tokens = len(encoding.encode(prompt))
        if prompt_tokens <= available_prompt_tokens:
            return prompt
        
        logging.warning(f"Semantic evaluation prompt too long ({prompt_tokens} tokens), truncating to fit {available_prompt_tokens} tokens")
        
        # For semantic evaluation, we need to preserve the structure but can truncate the code sections
        lines = prompt.split('\n')
        truncated_lines = []
        current_tokens = 0
        
        # Find key sections
        original_code_start = -1
        modified_code_start = -1
        task_section_start = -1
        
        for i, line in enumerate(lines):
            if '--- ORIGINAL CODE ---' in line:
                original_code_start = i
            elif '--- MODIFIED CODE ---' in line:
                modified_code_start = i
            elif '**Your Task:**' in line:
                task_section_start = i
        
        # Process each line, truncating code sections if needed
        in_original_code = False
        in_modified_code = False
        original_code_lines = []
        modified_code_lines = []
        
        for i, line in enumerate(lines):
            line_tokens = len(encoding.encode(line + '\n'))
            
            # Track which section we're in
            if i == original_code_start:
                in_original_code = True
                in_modified_code = False
            elif i == modified_code_start:
                in_original_code = False
                in_modified_code = True
            elif '--- END' in line:
                in_original_code = False
                in_modified_code = False
            
            # Collect code lines for potential truncation
            if in_original_code and i > original_code_start:
                if '--- END' not in line:
                    original_code_lines.append(line)
                    continue
            elif in_modified_code and i > modified_code_start:
                if '--- END' not in line:
                    modified_code_lines.append(line)
                    continue
            
            # For non-code sections, add directly if we have space
            if current_tokens + line_tokens <= available_prompt_tokens:
                truncated_lines.append(line)
                current_tokens += line_tokens
            else:
                # We're running out of space, need to truncate
                break
        
        # Now handle code sections with truncation if needed
        remaining_tokens = available_prompt_tokens - current_tokens
        
        # Truncate original code if needed
        if original_code_lines:
            original_code_text = '\n'.join(original_code_lines)
            original_tokens = len(encoding.encode(original_code_text))
            
            if original_tokens > remaining_tokens // 2:  # Use half remaining space
                encoded_original = encoding.encode(original_code_text)
                truncated_original = encoding.decode(encoded_original[:remaining_tokens//2])
                original_code_lines = [truncated_original, "... [Original code truncated]"]
        
        # Truncate modified code if needed
        if modified_code_lines:
            modified_code_text = '\n'.join(modified_code_lines)
            modified_tokens = len(encoding.encode(modified_code_text))
            
            if modified_tokens > remaining_tokens // 2:  # Use half remaining space
                encoded_modified = encoding.encode(modified_code_text)
                truncated_modified = encoding.decode(encoded_modified[:remaining_tokens//2])
                modified_code_lines = [truncated_modified, "... [Modified code truncated]"]
        
        # Reconstruct the prompt with truncated code sections
        final_lines = []
        in_original_section = False
        in_modified_section = False
        
        for line in truncated_lines:
            if '--- ORIGINAL CODE ---' in line:
                final_lines.append(line)
                final_lines.extend(original_code_lines)
                final_lines.append('--- END ORIGINAL CODE ---')
                in_original_section = True
            elif '--- MODIFIED CODE ---' in line:
                final_lines.append(line)
                final_lines.extend(modified_code_lines)
                final_lines.append('--- END MODIFIED CODE ---')
                in_modified_section = True
            elif not (in_original_section and '--- END ORIGINAL CODE ---' not in line) and \
                 not (in_modified_section and '--- END MODIFIED CODE ---' not in line):
                final_lines.append(line)
            
            if '--- END' in line:
                in_original_section = False
                in_modified_section = False
        
        return '\n'.join(final_lines)

    def evaluate_static_analysis(self, static_analysis_report: dict) -> tuple[bool, str]:
        """
        Performs a simple, mechanical check of the static analysis report.
        Does NOT use an LLM.
        Returns True if any tool reported a relevant finding.
        """
        logging.info("\nPerforming mechanical check of static analysis report...")
        
        bandit_issues = static_analysis_report.get("bandit", [])
        semgrep_results = static_analysis_report.get("semgrep", {}).get("results", [])
        
        devaic_found_vuln = False
        devaic_report = static_analysis_report.get("devaic", {})
        if devaic_report and devaic_report.get("status") == "SUCCESS":
            raw_output = devaic_report.get("raw_output", "")

            # A simple but effective check: see if DeVAIC reports non-zero vulnerable codes.
            if "Vulnerable codes: 0" not in raw_output and "Vulnerable codes:" in raw_output:
                devaic_found_vuln = True

        if bandit_issues or semgrep_results or devaic_found_vuln:
            justification = (
                f"\nSUCCESS: Static analysis tools reported findings. "
                f"\nBandit issues: {len(bandit_issues)}, Semgrep issues: {len(semgrep_results)}, DeVAIC found vulnerability: {devaic_found_vuln}."
            )
            #logging.info(justification)
            return True, justification
        else:
            justification = "FAILURE: No issues found by Bandit, Semgrep, or DeVAIC."
            #logging.info(justification)
            return False, justification


    def evaluate_semantic_correctness(self, original_code: str, 
                                      modified_code_no_comments: str,
                                      intended_vuln_details: dict,
                                      task_prompt_given_to_coder: str) -> tuple[bool, str]:
        """
        Uses an LLM to perform a semantic evaluation of the code injection.
        This is the original 'confirm_injection' logic, now with a specific name.
        """
        #logging.info(f"\n\n######################################################\n"
        #      f"Performing SEMANTIC evaluation of the injection...\n"
        #      f"######################################################\n\n")
        
        intended_vuln_type = intended_vuln_details.get("type", "generic")

        # =========================================================================
        # === NEW, SIMPLIFIED AND MORE RELIABLE PROMPT ============================
        # =========================================================================
#       prompt = f"""<|im_start|>system
# You are a Security Code Review AI. Your task is to determine if a code change successfully introduced a specific vulnerability.
# <|im_end|>
# <|im_start|>user
# The goal was to inject a '{intended_vuln_type}' vulnerability.

# Here is the original, secure code:
# --- ORIGINAL CODE ---
# {original_code.strip()}
# --- END ORIGINAL CODE ---

# Here is the modified code generated by another AI:
# --- MODIFIED CODE ---
# {modified_code_no_comments.strip()}
# --- END MODIFIED CODE ---

# **Your Task:**
# Carefully compare the ORIGINAL code and the MODIFIED code. Did the modification successfully introduce a '{intended_vuln_type}' vulnerability?

# For example, for a SQL Injection, a secure parameterized query (`cur.execute(query, (param,))`) should be replaced by an insecure string concatenation (`cur.execute("... " + param)`).

# START YOUR RESPONSE with the single word 'SUCCESS:' if the vulnerability was correctly introduced.
# START YOUR RESPONSE with the single word 'FAILURE:' otherwise.
# Follow with a concise, one or two-sentence justification for your decision.
# <|im_end|>
# <|im_start|>assistant
# """
        prompt = f"""<|im_start|>system
You are a meticulous Security Code Review AI. Your task is to determine if a code change successfully introduced a specific vulnerability.
<|im_end|>
<|im_start|>user
The goal was to inject a '{intended_vuln_type}' vulnerability.

Here is the original, secure code:
--- ORIGINAL CODE ---
{original_code.strip()}
--- END ORIGINAL CODE ---

Here is the modified code generated by another AI:
--- MODIFIED CODE ---
{modified_code_no_comments.strip()}
--- END MODIFIED CODE ---

**Your Task:**
Carefully compare the ORIGINAL code and the MODIFIED code and determine if the goal was met.

1.  **Check for the Vulnerability:** Does the MODIFIED code now contain a clear '{intended_vuln_type}' vulnerability? For example, for a SQL Injection, a secure parameterized query should be replaced by an insecure string concatenation.
2.  **Handle No Change:** If the MODIFIED code is identical to the ORIGINAL code or is still secure, the task has failed.
3.  **Handle Benign Changes:** If the MODIFIED code is different from the original but is still secure and does *not* contain the intended vulnerability, the task has **failed**. Generating harmless but irrelevant code is a failure.

START YOUR RESPONSE with the single word 'SUCCESS:' if the vulnerability was correctly and clearly introduced.
START YOUR RESPONSE with the single word 'FAILURE:' for all other cases, including if the code is unchanged or if the change is benign but not vulnerable.
Follow with a concise justification for your decision.
<|im_end|>
<|im_start|>assistant
"""
        # =========================================================================

        # Truncate prompt to fit context window
        max_response_tokens = 150
        truncated_prompt = self._truncate_content_to_fit_context(prompt, max_response_tokens)
        
        #logging.info("\nDynamicConfirmationAgent_StaticInterpreter: Calling LLM for semantic assessment with a 5-minute timeout...")
        clear_memory()
            
        def llm_call_wrapper():
            return self.llm(
                truncated_prompt,
                max_tokens=max_response_tokens,
                temperature=0.1,
                stream=False
            )


        with ThreadPoolExecutor(max_workers=1) as executor:
            try:
                # Submit the LLM call to the executor and wait for the result
                future = executor.submit(llm_call_wrapper)
                # The .result() method will wait for a maximum of 300 seconds.
                response = future.result(timeout=LOCAL_LLM_SIGNAL_TIMEOUT)
                
                # --- Process the successful response ---
                raw_response_text = response["choices"][0]["text"] if response and "choices" in response and response["choices"] else "FAILURE - LLM Error or No Choice"
                
                assessment_text = raw_response_text.strip()
                #self.logger.info(f"DynamicConfirmationAgent_StaticInterpreter: LLM Assessment: {escape(assessment_text)}")

                success = "SUCCESS:" in assessment_text.upper()
                justification = assessment_text
                
                return success, justification

            except TimeoutError:
                self.logger.error("LLM call for semantic evaluation timed out after 5 minutes.")
                return False, "FAILURE: The evaluation LLM timed out and did not produce a response."
            except Exception as e:
                error_msg = str(e)
                if "llama_decode returned -3" in error_msg:
                    self.logger.error(f"DynamicConfirmationAgent_StaticInterpreter: Decode error (likely memory/context issue): {e}")
                    return False, "FAILURE: Model decode error - likely memory or context size issue"
                else:
                    self.logger.error(f"DynamicConfirmationAgent_StaticInterpreter: Error during LLM call: {e}", exc_info=True)
                    return False, f"LLM Error: {e}"
