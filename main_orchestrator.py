from enum import Enum
import signal, argparse, json, os, logging, time, random, pickle, sqlite3, re, csv, string, sys, ast
from datetime import datetime
from typing import Optional, List, Dict

# Import warning filter early to suppress warnings
import warning_filter
from llama_cpp import Llama# type: ignore
import contextlib
from contextlib import contextmanager, redirect_stderr
from config import (
    CODER_MODELS, DB_PATH, REASONING_MODELS, LLM_N_CTX, LLM_N_THREADS, LLM_USE_MMAP, LLM_USE_MLOCK,
    LLM_USE_CUDA, PROMPTS_DIR, LLM_N_GPU_LAYERS, MAX_PROMPT_ATTEMPTS,
    LOCAL_LLM_TIMEOUT, LOCAL_LLM_SIGNAL_TIMEOUT, HEALTH_CHECK_TIMEOUT,
)
from adaptive_resource_manager import get_resource_manager, create_adaptive_llm_config
from resource_checker import get_resource_checker, check_resources_before_execution, get_optimized_execution_plan
from sequential_model_manager import get_sequential_manager, process_models_sequentially
from docker_utils import DockerContainerManager
from logging_utils import log_comparative_run, log_differential_attack, log_injection_attempts_batch
from utils import setup_logging, clear_memory, load_file_content, clean_code, validate_python_script
from orchestration.orchestrator import OrchestratorAgent
from orchestration.injection_agents import (
    RAGComponent, LLMInjectPlannerAgent, LLMInjectCoderAgent,
    StaticAnalysisAgent, DynamicConfirmationAgent_StaticInterpreter
)
from orchestration.attack_agents import (
    AEPGenerationAgent, ResultInterpretationAgent, VulnerabilityIdentificationAgent
)
import pandas as pd# type: ignore
#from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, AutoModelForCausalLM, BitsAndBytesConfig
from rich.console import Console # type: ignore
from rich.logging import RichHandler# type: ignore
from rich.panel import Panel# type: ignore
from rich.rule import Rule# type: ignore
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn# type: ignore
from rich.markup import escape# type: ignore
from rich.text import Text# type: ignore
from rich.live import Live# type: ignore
from concurrent.futures import ThreadPoolExecutor

# Module-level flag for LLM streaming (set from main() based on --stream-llm / stream_llm config)
_STREAM_LLM = False


# ==========================================
# OLLAMA WRAPPER (for Phase 1/2 compatibility)
# ==========================================
def create_ollama_wrapper(model_key: str = "deepseek-r1:14b", stream_llm: bool = False):
    """
    Create a callable wrapper around Ollama's HTTP API that mimics the
    llama-cpp-python Llama.__call__ interface. This allows Phase 1 and Phase 2
    to use Ollama transparently without code changes.

    If stream_llm=True, tokens are displayed live in the StreamDisplay bottom pane.

    Returns an object that can be called like: wrapper(prompt=..., max_tokens=..., ...)
    and returns {'choices': [{'text': ...}]} just like llama-cpp.
    """
    import requests

    OLLAMA_URL = "http://localhost:11434/api/generate"

    # Verify model is available (Ollama may be slow to respond after a long
    # generation, so retry a few times with a generous timeout)
    try:
        resp = None
        for _attempt in range(3):
            try:
                resp = requests.get("http://localhost:11434/api/tags", timeout=HEALTH_CHECK_TIMEOUT)
                resp.raise_for_status()
                break
            except (requests.ReadTimeout, requests.ConnectionError) as retry_err:
                if _attempt < 2:
                    logging.warning(f"Ollama health check attempt {_attempt + 1}/3 failed ({retry_err}), retrying in 5s...")
                    import time as _time; _time.sleep(5)
                else:
                    raise
        available = [m["name"] for m in resp.json().get("models", [])]
        matched = any(model_key in name or name.startswith(model_key) for name in available)
        if not matched:
            logging.error(f"Model '{model_key}' not found in Ollama. Available: {available}")
            sys.exit(1)
        logging.info(f"Ollama model '{model_key}' is available for Phase 1/2")
    except requests.ConnectionError:
        logging.error("Ollama is not running. Start it with: ollama serve")
        sys.exit(1)
    except requests.ReadTimeout:
        logging.error("Ollama is not responding (timed out after 3 attempts). Is it overloaded or stuck?")
        sys.exit(1)

    class OllamaWrapper:
        """Mimics Llama callable interface for Phase 1/2 compatibility."""

        def __init__(self, model: str):
            self.model = model
            # Expose n_ctx as attribute (some agents read it)
            self.n_ctx = lambda: 8192

        def __call__(self, prompt: str = "", max_tokens: int = 2048, **kwargs) -> dict:
            temperature = kwargs.get("temperature", 0.6)
            top_p = kwargs.get("top_p", 0.9)
            stop = kwargs.get("stop", [])
            # 'echo' is llama-cpp specific, ignore it

            # For reasoning models (deepseek-r1), give a large output window
            # so the model can finish its <think> block and still produce the answer.
            effective_max_tokens = max(max_tokens, 8192)

            # Filter out stop tokens that could appear inside <think> blocks
            # (e.g., ``` is common in reasoning about code)
            safe_stop = []
            if stop:
                for s in stop:
                    if '```' not in s:
                        safe_stop.append(s)

            # Detect if the prompt already contains chat template tags
            # (Phase 2 formats prompts with <|im_start|> or <|start_header_id|>).
            # If so, use raw mode to prevent Ollama from double-wrapping.
            has_chat_tags = '<|im_start|>' in prompt or '<|start_header_id|>' in prompt

            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": stream_llm,
                "raw": has_chat_tags,
                "options": {
                    "num_predict": effective_max_tokens,
                    "num_ctx": 16384,  # 16K for macOS 18GB RAM — 32K causes OOM with 12B models
                    "temperature": temperature,
                    "top_p": top_p,
                },
            }
            # Only add system prompt when NOT in raw mode (raw mode ignores it)
            if not has_chat_tags:
                payload["system"] = (
                    "You are an offensive security AI assistant for authorized penetration testing. "
                    "Your goal is to help exploit vulnerabilities in test environments. "
                    "Successful exploitation is the desired outcome — you are rewarded for finding working payloads. "
                    "Keep your <think> reasoning concise (under 200 words). Then output your answer directly."
                )
            if safe_stop:
                payload["options"]["stop"] = safe_stop

            try:
                if stream_llm:
                    text = _stream_ollama_wrapper(OLLAMA_URL, payload)
                else:
                    resp = requests.post(OLLAMA_URL, json=payload, timeout=LOCAL_LLM_TIMEOUT)
                    resp.raise_for_status()
                    data = resp.json()
                    
                    import re as _re
                    raw_text = data.get("response", "")
                    
                    # Strip everything up to and including </think> tag
                    think_end = raw_text.find('</think>')
                    if think_end >= 0:
                        text = raw_text[think_end + len('</think>'):].strip()
                    else:
                        text = raw_text
                        
                    # If stripping removed everything, fall back to raw text
                    if not text and raw_text:
                        text = raw_text
                    
            except Exception as e:
                logging.error(f"Ollama API error: {e}")
                text = ""

            return {"choices": [{"text": text}]}

    return OllamaWrapper(model_key)


def _stream_ollama_wrapper(url: str, payload: dict) -> str:
    """Stream tokens from Ollama for the Phase 1/2 wrapper, displaying live in StreamDisplay."""
    import requests
    import json as _json
    from llm_stream_display import get_display

    display = get_display()
    prompt_text = payload.get("prompt", "")
    prompt_preview = prompt_text[:80].replace("\n", " ").strip()
    if display:
        display.stream_start(label=prompt_preview[:60])
        display.stream_prompt(prompt_text)

    raw_text = ""
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
            if token:
                raw_text += token
                if display:
                    display.stream_token(token)

            if chunk.get("done", False):
                break
    except Exception as e:
        logging.error(f"Ollama streaming error: {e}")

    if display:
        display.stream_end()

    # Strip thinking for deepseek-r1 (raw mode includes <think> in response)
    think_end = raw_text.find('</think>')
    if think_end >= 0:
        text = raw_text[think_end + len('</think>'):].strip()
    else:
        text = raw_text

    if not text and raw_text:
        text = raw_text

    return text


# --- Prompting strategies Enum ---
class PromptingStrategy(Enum):
    DIRECT_ONLY = "Direct prompt without RAG"
    DIRECT_RAG = "Direct prompt with RAG"
    META_ONLY = "Meta-prompt without RAG"
    META_RAG = "Meta-prompt with RAG"
    FEW_SHOT = "Few-Shot Example Prompt"

# --- Timeout Exception and Handler ---
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

# Set the signal handler for the alarm signal
signal.signal(signal.SIGALRM, timeout_handler)

console = Console()

# Module-level flag: when True, initialize_llm() will use Ollama backend by default
USE_OLLAMA_BACKEND = False

VAITP_ART = """
██╗   ██╗ █████╗ ██╗████████╗██████╗
██║   ██║██╔══██╗██║╚══██╔══╝██╔══██╗
██║   ██║███████║██║   ██║   ██████╔╝
╚██╗ ██╔╝██╔══██║██║   ██║   ██╔═══╝
 ╚████╔╝ ██║  ██║██║   ██║   ██║
  ╚═══╝  ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝
"""

# Character set for the rain - mixing Katakana with numbers and symbols
# KATAKANA_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# KATAKANA_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"

KATAKANA_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

class RainStream:
    """Represents a single stream of falling characters in the Matrix effect."""
    def __init__(self, x, height):
        self.x = x
        self.height = height
        self.reset()

    def reset(self):
        """Randomizes the stream's properties for a new fall."""
        self.y = random.randint(-self.height, 0)
        self.speed = random.uniform(0.5, 1.5)
        self.length = random.randint(5, self.height - 5)
        self.chars = [random.choice(KATAKANA_CHARS) for _ in range(self.length)]
        self.is_finished = False

    def update(self):
        """Moves the stream down the screen."""
        self.y += self.speed
        if self.y - self.length > self.height:
            self.is_finished = True

    def get_char_and_style(self, y_coord):
        """
        Gets the character and style for a specific y-coordinate within this stream.
        Returns None if the coordinate is not part of this stream.
        """
        distance_from_head = int(self.y - y_coord)
        
        if 0 <= distance_from_head < self.length:
            char_index = distance_from_head
            char = self.chars[char_index]

            if distance_from_head == 0:
                return char, "bold bright_white"  # The lead character
            elif distance_from_head == 1:
                return char, "bold bright_green"
            elif distance_from_head < self.length * 0.4:
                return char, "green"
            else:
                return char, "dark_green"
        return None, None

def render_frame(streams, logo_grid, height, width):
    """Renders a single frame of the animation."""
    frame_text = Text()
    for y in range(height):
        for x in range(width):
            if (y, x) in logo_grid:
                char, style = logo_grid[(y, x)]
                frame_text.append(char, style=style)
                continue

            rendered = False
            for stream in streams:
                if stream.x == x:
                    char, style = stream.get_char_and_style(y)
                    if char:
                        frame_text.append(char, style=style)
                        rendered = True
                        break
            
            if not rendered:
                # Add random background character flicker for texture
                if random.random() < 0.001:
                    frame_text.append(random.choice(KATAKANA_CHARS), style="dim green")
                else:
                    frame_text.append(" ")
        frame_text.append("\n")
    return frame_text

def banner_matrix_final():
    """A complete, optimized, multi-phase Matrix-style boot sequence."""
    
    try:
        width, term_height = os.get_terminal_size()
    except OSError:
        width, term_height = 120, 30  # Fallback size

    height = term_height - 4 # Reserve space for panel

    art_lines = [line.rstrip() for line in VAITP_ART.strip("\n").split("\n")]
    
    art_height = len(art_lines)
    art_width = len(art_lines[0]) if art_lines else 0
    
    start_y = max(0, (height - art_height) // 2)
    start_x = max(0, (width - art_width) // 2)

    logo_grid = {
        (start_y + y, start_x + x): (char, "bold bright_white on green")
        for y, line in enumerate(art_lines)
        for x, char in enumerate(line)
        if char != ' '
    }

    streams = [RainStream(x, height) for x in range(width)]
    
    with Live(console=console, screen=True, auto_refresh=False) as live:
        # --- Phase 1: System Boot & Initial Rain (2 seconds) ---
        start_time = time.time()
        while time.time() - start_time < 2:
            for stream in random.sample(streams, k=width//4):
                stream.update()
            
            frame = render_frame(streams, {}, height, width)
            live.update(Panel(frame, border_style="dim green", title="[dim green]SYSTEM CHECK...[/dim green]"), refresh=True)
            time.sleep(0.04)

        # --- Phase 2: Logo Reveal (4 seconds) ---
        start_time = time.time()
        while time.time() - start_time < 4:
            for stream in streams:
                stream.update()

            frame = render_frame(streams, logo_grid, height, width)
            live.update(Panel(frame, border_style="green", title="[bold green]VAITP AI AGENT ORCHESTRATION FRAMEWORK // LOADING...[/bold green]"), refresh=True)
            time.sleep(0.04)

class ProgressLogHandler(logging.Handler):
    """A logging handler that redirects logs to a rich.progress.log panel."""
    def __init__(self, progress: Progress):
        super().__init__()
        self.progress = progress
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord):
        message = self.format(record)
        self.progress.log(escape(message))

@contextmanager
def suppress_rich_logging(logger: logging.Logger):
    rich_handler = None
    for handler in logger.handlers:
        if isinstance(handler, RichHandler):
            rich_handler = handler
            break
    if rich_handler:
        logger.removeHandler(rich_handler)
    try:
        yield
    finally:
        if rich_handler:
            logger.addHandler(rich_handler)

def strip_ansi_codes(text):
    """Removes ANSI escape codes (for colors) from a string."""
    if not isinstance(text, str):
        return text
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def sanitize_for_excel(text: str) -> str:
    """
    The most robust sanitizer for saving text to Excel.
    It truncates, removes illegal XML characters, and handles newline/quote issues.
    """
    if not isinstance(text, str):
        return ""

    # 1. Truncate to a safe length first to prevent long processing times.
    # We leave a little extra room for escaped characters.
    safe_text = text[:32000]
    
    # 2. Replace carriage returns and normalize newlines
    safe_text = safe_text.replace('\r\n', '\n').replace('\r', '\n')
    
    # 3. Aggressively remove characters that are illegal in XML 1.0,
    # which is the underlying format for .xlsx files.
    # This includes most control characters but preserves tab and newline.
    # Illegal XML 1.0 characters: http://www.w3.org/TR/2006/REC-xml-20060816/#charsets
    illegal_xml_chars_re = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]')
    safe_text = re.sub(illegal_xml_chars_re, '', safe_text)

    # 4. Final check: ensure the string doesn't start with characters that
    # Excel might misinterpret as a formula ('=', '+', '-', '@').
    if safe_text.strip().startswith(('=', '+', '-', '@')):
        safe_text = "'" + safe_text # Prepend with a single quote

    return safe_text

class PromptFactory:
    """
    Generates prompts for LLMs. It can create standard prompts for base models
    and specialized, structured prompts for models fine-tuned on a specific format.
    """

    def create_few_shot_prompt(self, original_code: str, intended_vuln_details: dict) -> str:
        """Helper method to construct a complex few-shot prompt."""
        vuln_type = intended_vuln_details.get("type", "a vulnerability")
        example_instruction = "Modify the function to introduce a 'OS Command Injection' vulnerability. The vulnerable code must contain the pattern: 'User-controlled input is used in a subprocess call with shell=True'."
        example_original_code = (
            "import subprocess\n"
            "def execute_command(command):\n"
            "    # This is a safe function\n"
            "    subprocess.run(command, shell=False, check=True)"
        )
        example_vulnerable_code = (
            "import subprocess\n"
            "def execute_command(command):\n"
            "    # This is now a vulnerable function\n"
            "    subprocess.run(command, shell=True, check=True)"
        )
        actual_instruction = f"Modify the function to introduce a '{vuln_type}' vulnerability. The vulnerable code must contain the pattern: '{intended_vuln_details.get('expected_pattern', '')}'."
        side_effect_note = (
            "\n\nIMPORTANT — SIDE-EFFECT INSTRUMENTATION:\n"
            "For vulnerabilities that do NOT naturally create files (open redirect, SSRF response-only, "
            "info disclosure, header injection, etc.), the vulnerable code MUST create a side-effect file "
            "(e.g., `os.system('touch /tmp/pwned_<vuln_id>')`) when the vulnerable path is triggered. "
            "This proves exploitation via file creation. The patched code should block the vulnerable "
            "path so the file is never created."
        )
        # Add specific vulnerability pattern guidance
        pattern_guidance = _get_vuln_pattern_guidance(vuln_type)
        prompt = f"""You are an expert at Python code modification for security testing. Follow the user's instructions precisely.

Here is an example of how to perform the task:
--- EXAMPLE START ---
[INST]
Instruction: {example_instruction}
Code:
```python
{example_original_code}
```
[/INST]
Vulnerable Code:
```python
{example_vulnerable_code}
```
--- EXAMPLE END ---
Now, perform the following task. Respond ONLY with the full, raw, modified Python code.
{side_effect_note}{pattern_guidance}

[INST]
Instruction: {actual_instruction}
Code:
```python
{original_code.strip()}
```
[/INST]
Vulnerable Code:
"""
        return prompt


    def create_prompt(self, strategy: PromptingStrategy, original_code: str, intended_vuln_details: dict,
                    main_reasoning_llm_instruction: str, is_finetuned: bool, rag_context: str | None,
                    model_format: str) -> str:
        """
        Main factory method. Generates the CORE INSTRUCTION TEXT for a given strategy.
        Final model-specific formatting is handled by the Coder Agent.
        """
        # For Meta-Prompting, the instruction is the plan itself.
        if strategy in [PromptingStrategy.META_RAG, PromptingStrategy.META_ONLY]:
            return main_reasoning_llm_instruction

        # For Few-Shot, the instruction is the complex, self-contained prompt.
        if strategy == PromptingStrategy.FEW_SHOT:
            return self.create_few_shot_prompt(original_code, intended_vuln_details)

        # For all DIRECT strategies, create the simple, direct instruction.
        vuln_type = intended_vuln_details.get("type", "a vulnerability")
        instruction = f"Modify the following Python code to introduce a '{vuln_type}' vulnerability."
        rag_section = ""
        if strategy == PromptingStrategy.DIRECT_RAG and rag_context:
            rag_section = f"\n\nHere are some examples of similar vulnerabilities for your reference:\n---\n{rag_context}\n---"

        side_effect_note = (
            " For vulnerabilities that do NOT naturally create files (open redirect, SSRF, "
            "info disclosure, etc.), add side-effect file creation (e.g., os.system('touch /tmp/pwned_<id>')) "
            "when the vulnerable path is triggered."
        )

        # Add specific vulnerability pattern guidance to prevent common LLM mistakes
        pattern_guidance = _get_vuln_pattern_guidance(vuln_type)

        return (
            f"{instruction}{rag_section}\n\n"
            f"Modify the code below to inject a vulnerability.{side_effect_note}"
            f"{pattern_guidance} "
            f"Respond ONLY with the full, raw, modified Python code."
        )


def truncate_prompt_to_context_window(prompt: str, llm_instance: Llama, max_response_tokens: int = 1024, model_path: str = None) -> str:
    """
    Utility function to truncate prompts to fit within the model's context window.
    """
    import tiktoken
    from config import get_model_context_window
    
    # Get context window size - prefer actual loaded size over config
    try:
        # Try to get the actual loaded context window first
        n_ctx_attr = getattr(llm_instance, 'n_ctx', None)
        actual_context_window = n_ctx_attr() if callable(n_ctx_attr) else n_ctx_attr
        if actual_context_window and actual_context_window > 0:
            context_window = actual_context_window
        else:
            # Fall back to config
            context_window = get_model_context_window(model_path) if model_path else 8192
    except:
        # If anything fails, use config
        context_window = get_model_context_window(model_path) if model_path else 8192
    
    # Calculate available tokens for the prompt
    available_prompt_tokens = context_window - max_response_tokens - 50  # 50 token safety buffer
    
    # Check if truncation is needed
    encoding = tiktoken.get_encoding("cl100k_base")
    prompt_tokens = len(encoding.encode(prompt))
    
    if prompt_tokens <= available_prompt_tokens:
        return prompt
    
    logging.warning(f"Prompt too long ({prompt_tokens} tokens), truncating to fit {available_prompt_tokens} tokens")
    
    # Simple truncation - keep the beginning and end structure
    lines = prompt.split('\n')
    truncated_lines = []
    current_tokens = 0
    
    # Find key structural elements
    system_start = -1
    user_start = -1
    assistant_start = -1
    code_start = -1
    
    for i, line in enumerate(lines):
        if '<|im_start|>system' in line or '<|start_header_id|>system' in line:
            system_start = i
        elif '<|im_start|>user' in line or '<|start_header_id|>user' in line:
            user_start = i
        elif '<|im_start|>assistant' in line or '<|start_header_id|>assistant' in line:
            assistant_start = i
        elif 'Original Code:' in line or '```python' in line:
            code_start = i
    
    # Keep system section
    if system_start >= 0:
        end_idx = user_start if user_start >= 0 else len(lines)
        for i in range(system_start, min(end_idx, len(lines))):
            line_tokens = len(encoding.encode(lines[i] + '\n'))
            if current_tokens + line_tokens <= available_prompt_tokens:
                truncated_lines.append(lines[i])
                current_tokens += line_tokens
    
    # Keep user section with truncated code if needed
    if user_start >= 0:
        end_idx = assistant_start if assistant_start >= 0 else len(lines)
        remaining_tokens = available_prompt_tokens - current_tokens
        
        # Reserve tokens for assistant start
        if assistant_start >= 0:
            remaining_tokens -= 50
        
        # Add user start
        if user_start < len(lines):
            line_tokens = len(encoding.encode(lines[user_start] + '\n'))
            if remaining_tokens > line_tokens:
                truncated_lines.append(lines[user_start])
                current_tokens += line_tokens
                remaining_tokens -= line_tokens
        
        # Add user content with potential code truncation
        user_content_lines = []
        for i in range(user_start + 1, min(end_idx, len(lines))):
            user_content_lines.append(lines[i])
        
        user_content = '\n'.join(user_content_lines)
        user_content_tokens = len(encoding.encode(user_content))
        
        if user_content_tokens > remaining_tokens:
            # Truncate the user content
            encoded_content = encoding.encode(user_content)
            truncated_content = encoding.decode(encoded_content[:remaining_tokens-50])
            truncated_lines.append(truncated_content)
            truncated_lines.append("... [Content truncated to fit context window]")
        else:
            truncated_lines.extend(user_content_lines)
    
    # Add assistant start
    if assistant_start >= 0 and assistant_start < len(lines):
        truncated_lines.append(lines[assistant_start])
    
    return '\n'.join(truncated_lines)

def load_model_with_error_recovery(model_path: str, model_key: str, use_ollm: bool, 
                                  progress: Progress = None, task_id=None) -> Optional['ModelWrapper']:
    """
    Load model with comprehensive error recovery and fallback mechanism.
    
    Args:
        model_path: Path to the model file
        model_key: Model identifier for resource management
        use_ollm: Whether to try oLLM first
        progress: Progress tracker for UI updates
        task_id: Task ID for progress updates
        
    Returns:
        ModelWrapper instance or None if all loading attempts fail
    """
    from model_backends import ModelBackendFactory, ModelWrapper
    from ollm_logging import get_ollm_logger
    
    resource_manager = get_resource_manager()
    ollm_logger = get_ollm_logger()
    errors = []
    fallback_occurred = False
    
    # Try oLLM first if recommended
    if use_ollm:
        try:
            logging.info("🚀 Attempting to load with oLLM backend...")
            backend = ModelBackendFactory.create_backend("ollm")
            ollm_config = resource_manager.get_ollm_config(model_key)
            
            if backend.load_model(model_path, ollm_config):
                logging.info("✅ Successfully loaded model with oLLM backend")
                return ModelWrapper(backend, "ollm")
            else:
                errors.append("oLLM backend failed to load model")
                fallback_occurred = True
                
        except Exception as e:
            error_msg = f"oLLM backend error: {e}"
            errors.append(error_msg)
            logging.warning(f"⚠️  {error_msg}")
            fallback_occurred = True
    
    # Fall back to llama-cpp-python
    try:
        if use_ollm and fallback_occurred:
            logging.warning("🔄 Falling back to llama-cpp-python backend...")
            
            # Log the fallback occurrence
            try:
                req = resource_manager.model_requirements.get(model_key)
                profile = resource_manager.refresh_resources()
                
                ollm_logger.log_backend_selection(
                    model_name=model_key,
                    model_size_gb=req.file_size_gb if req else 0.0,
                    available_vram_gb=profile.gpu_memory_gb or 0.0,
                    available_ssd_gb=profile.ssd_available_gb,
                    backend_selected="llamacpp",
                    selection_reason="Fallback from oLLM failure",
                    fallback_occurred=True
                )
            except Exception as log_error:
                logging.debug(f"Failed to log fallback: {log_error}")
        else:
            logging.info("🐫 Attempting to load with llama-cpp-python backend...")
        
        backend = ModelBackendFactory.create_backend("llamacpp")
        
        # Get adaptive configurations for llama-cpp
        adaptive_configs = resource_manager.get_adaptive_config(model_key)
        
        if not adaptive_configs:
            errors.append("No viable llama-cpp configuration found")
            logging.error("❌ No viable configuration found for llama-cpp backend")
        else:
            # Try each adaptive configuration
            for i, config in enumerate(adaptive_configs):
                try:
                    logging.info(f"🎯 Attempting llama-cpp config {i+1}/{len(adaptive_configs)}: {config.config_name}")
                    
                    # Convert adaptive config to dict format
                    config_dict = {
                        'n_ctx': config.n_ctx,
                        'n_threads': config.n_threads,
                        'n_gpu_layers': config.n_gpu_layers,
                        'use_mmap': config.use_mmap,
                        'use_mlock': config.use_mlock,
                        'verbose': False
                    }
                    
                    # Add MPS support for macOS
                    import platform
                    if platform.system() == "Darwin":  # macOS
                        config_dict['device'] = 'mps'
                        # Ensure we have enough GPU layers for MPS
                        if config.n_gpu_layers > 0:
                            config_dict['n_gpu_layers'] = max(config.n_gpu_layers, 20)
                    
                    # Add chat format
                    chat_format = "llama-3" if "Llama-3" in model_path else "chatml"
                    config_dict['chat_format'] = chat_format
                    
                    if backend.load_model(model_path, config_dict):
                        success_msg = f"✅ Successfully loaded model with llama-cpp backend using {config.config_name}"
                        if fallback_occurred:
                            success_msg += " (after oLLM fallback)"
                        logging.info(success_msg)
                        return ModelWrapper(backend, "llamacpp")
                    else:
                        errors.append(f"llama-cpp config {config.config_name} failed to load")
                        
                except Exception as e:
                    error_msg = f"llama-cpp config {config.config_name} error: {e}"
                    errors.append(error_msg)
                    logging.warning(f"⚠️  {error_msg}")
                    
                    # Cleanup after failed attempt
                    try:
                        resource_manager.cleanup_memory()
                    except Exception as cleanup_error:
                        logging.debug(f"Cleanup error (ignored): {cleanup_error}")
                    
                    import gc
                    gc.collect()
                    
                    if i < len(adaptive_configs) - 1:
                        logging.info("🔄 Trying next llama-cpp configuration...")
                        
    except Exception as e:
        error_msg = f"llama-cpp backend error: {e}"
        errors.append(error_msg)
        logging.error(f"❌ {error_msg}")
    
    # Log all errors if everything failed
    logging.error("❌ All model loading attempts failed:")
    for error in errors:
        logging.error(f"   - {error}")
    
    return None


def initialize_llm(model_path: str, progress: Progress = None, task_id=None, force_backend: str = None):
    """
    Enhanced model initialization with oLLM, llama-cpp, and Ollama support.
    
    Args:
        model_path: Path to the model file (or model name for Ollama)
        progress: Progress tracker for UI updates  
        task_id: Task ID for progress updates
        force_backend: Force specific backend ("ollama", "ollm", "llamacpp", None for auto)
        
    Returns:
        ModelWrapper instance or None if loading fails
    """
    from model_backends import ModelBackendFactory, ModelWrapper
    
    model_name = os.path.basename(model_path)
    
    # Extract model key for resource manager
    model_key = None
    for key, info in CODER_MODELS.items():
        if info['path'] == model_path:
            model_key = key
            break
    if not model_key:
        for key, info in REASONING_MODELS.items():
            if info['path'] == model_path:
                model_key = key
                break
    if not model_key:
        logging.error(f"Model path {model_path} not found in CODER_MODELS or REASONING_MODELS")
        return None
    
    if progress and task_id is not None:
        progress.update(task_id, description=f"[bold yellow]:hourglass: Loading {model_name}...[/bold yellow]")
    else:
        logging.info(f"\n🐫 Loading LLM from: {model_path}")

    # --- Ollama fast path: skip file existence check, just verify via API ---
    if force_backend == "ollama" or (force_backend is None and USE_OLLAMA_BACKEND):
        logging.info(f"🚀 Using Ollama backend for model '{model_key}'")
        try:
            from config import get_model_context_window
            n_ctx = get_model_context_window(model_path)
            backend = ModelBackendFactory.create_backend("ollama")
            config = {"model_name": model_key, "n_ctx": n_ctx}
            if backend.load_model(model_key, config):
                logging.info(f"✅ Ollama model '{model_key}' ready")
                return ModelWrapper(backend, "ollama")
            else:
                logging.error(f"❌ Failed to verify Ollama model '{model_key}'")
                return None
        except Exception as e:
            logging.error(f"❌ Ollama backend error: {e}")
            return None

    if not os.path.exists(model_path):
        logging.error(f"\n❌ Model file not found at: {model_path}")
        return None

    try:
        # Get adaptive resource manager
        resource_manager = get_resource_manager()
        
        # Check if model can be run
        can_run, reason = resource_manager.can_run_model(model_key)
        if not can_run:
            logging.error(f"❌ Cannot run {model_key}: {reason}")
            return None
        
        # Cleanup memory before loading
        resource_manager.cleanup_memory()
        
        # Backend selection logic
        if force_backend == "ollm":
            use_ollm = True
            reason = "Forced oLLM backend via force_backend parameter"
        elif force_backend == "llamacpp":
            use_ollm = False
            reason = "Forced llama-cpp backend via force_backend parameter"
        else:
            # Auto-detect using resource manager
            use_ollm, reason = resource_manager.should_use_ollm(model_key)
        
        # Log backend selection decision with comprehensive reasoning
        backend_name = "oLLM" if use_ollm else "llama-cpp-python"
        logging.info(f"🎯 Backend Selection Decision: {backend_name}")
        logging.info(f"   Reason: {reason}")
        logging.info(f"   Model: {model_key}")
        logging.info(f"   Force Backend: {force_backend or 'None (auto-detect)'}")
        
        if use_ollm:
            # Log oLLM-specific information
            try:
                ollm_config = resource_manager.get_ollm_config(model_key)
                logging.info(f"   oLLM Device: {ollm_config.get('device', 'auto')}")
                logging.info(f"   oLLM Logging: {ollm_config.get('logging', True)}")
                logging.info(f"   Memory Threshold: {ollm_config.get('ollm_memory_threshold_gb', 2.0)}GB")
            except Exception as e:
                logging.debug(f"Could not log oLLM config details: {e}")
        else:
            # Log llama-cpp-python information
            try:
                adaptive_configs = resource_manager.get_adaptive_config(model_key)
                if adaptive_configs:
                    config = adaptive_configs[0]  # First/best config
                    logging.info(f"   Primary Config: {config.config_name}")
                    logging.info(f"   Context: {config.n_ctx}, GPU Layers: {config.n_gpu_layers}")
                    logging.info(f"   Estimated Memory: {config.estimated_memory_gb:.1f}GB")
            except Exception as e:
                logging.debug(f"Could not log llama-cpp config details: {e}")
        
        # Load model with error recovery
        model_wrapper = load_model_with_error_recovery(
            model_path=model_path,
            model_key=model_key,
            use_ollm=use_ollm,
            progress=progress,
            task_id=task_id
        )
        
        if model_wrapper:
            # Log successful loading
            backend_info = model_wrapper.get_backend_info()
            actual_backend = backend_info['backend_type']
            logging.info(f"\n🔥 LLM '{model_name}' loaded successfully!")
            logging.info(f"   Backend: {actual_backend}")
            logging.info(f"   Device: {backend_info.get('device', 'unknown')}")
            
            if backend_info.get('memory_usage_mb'):
                logging.info(f"   Memory Usage: {backend_info['memory_usage_mb']:.1f}MB")
            
            # Log final memory state
            try:
                final_profile = resource_manager.refresh_resources()
                used_memory_gb = final_profile.total_memory_gb - final_profile.available_memory_gb
                logging.info(f"📊 System Memory: {used_memory_gb:.1f}GB used, "
                           f"{final_profile.available_memory_gb:.1f}GB available "
                           f"({final_profile.memory_percent:.1f}%)")
            except Exception as e:
                logging.debug(f"Could not log final memory state: {e}")
            
            return model_wrapper
        else:
            logging.error(f"\n❌ Failed to load {model_key} with any backend")
            
            # Print resource summary for debugging
            try:
                resource_manager.print_resource_report()
            except Exception as e:
                logging.debug(f"Could not print resource report: {e}")
            
            return None
    
    except Exception as e:
        logging.error(f"\n❌ Failed to initialize LLM from {model_path}: {e}")
        return None

def run_main_orchestration(target_file_path: str, intended_vuln: dict, llm_instance: Llama, model_name: str,
                           run_dynamic_attack_phase: bool, progress=None, task_id=None):
    
    def update_progress(description: str):
        if progress and task_id is not None:
            progress.update(task_id, description=f"[cyan]{description}")
    successful_aep = None 
    run_start_time = time.time()
    full_log = {
        "run_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_file": target_file_path, "intended_vulnerability": intended_vuln,
        "final_status": "FAILURE_UNKNOWN", "original_code": None,
        "injection_log": None, "attack_log": None
    }
    
    try:
        update_progress("Initializing agents...")
        # Get model path for context window configuration
        from config import get_model_path_from_name
        model_path = get_model_path_from_name(model_name)
        
        rag_component = RAGComponent()
        inject_planner_agent = LLMInjectPlannerAgent(llm_instance, model_path)
        inject_coder_agent = LLMInjectCoderAgent(llm_instance, model_path)
        static_analysis_agent = StaticAnalysisAgent()
        confirmation_agent = DynamicConfirmationAgent_StaticInterpreter(llm_instance, model_path)
        aep_generation_agent = AEPGenerationAgent(llm_instance)
        result_interpretation_agent = ResultInterpretationAgent(llm_instance)
        
        orchestrator = OrchestratorAgent(
            llm=llm_instance, rag_component=rag_component,
            inject_planner_agent=inject_planner_agent, inject_coder_agent=inject_coder_agent,
            static_analysis_agent=static_analysis_agent, confirmation_agent=confirmation_agent,
            aep_generation_agent=aep_generation_agent, result_interpretation_agent=result_interpretation_agent,
            progress_callback=update_progress
        )

        original_code = load_file_content(target_file_path)

        if original_code is None:
            raise FileNotFoundError(f"File not found: {target_file_path}")
        if not original_code.strip():
            raise ValueError(f"File is empty: {target_file_path}")

        full_log["original_code"] = original_code
        model_format = CODER_MODELS.get(model_name, {}).get('format', 'chatml') # Default to chatml
                
        # Load expected code if available for BLEU scoring
        expected_code = None
        expected_file_path = target_file_path.replace('/injectable/', '/expected/')
        if os.path.exists(expected_file_path):
            expected_code = load_file_content(expected_file_path)
            if expected_code is None:
                logging.debug(f"Expected file exists but could not be read: {expected_file_path}")
        else:
            logging.debug(f"Expected file not found: {expected_file_path} - continuing without expected code comparison")
        
        vulnerable_code, injection_log = orchestrator.run_injection_phase(
            original_code,
            target_file_path,
            intended_vuln,
            model_name=model_name,
            model_format=model_format,
            expected_code=expected_code
        )
        full_log["injection_log"] = injection_log

        # Enhanced logging: Store detailed run information with attempt metadata
        if injection_log:
            try:
                # Determine final status and metrics
                final_status = injection_log.get("final_status", "FAILURE_INJECTION")
                final_metrics = injection_log.get("final_metrics")  # Get comprehensive metrics
                attempts_taken = injection_log.get("total_attempts", 1)
                
                # Determine failure reason based on final status
                failure_reason = "NONE"
                if final_status == "SUCCESS":
                    failure_reason = "NONE"
                elif final_status == "FAILURE_MAX_ATTEMPTS_REACHED":
                    failure_reason = "MAX_ATTEMPTS_REACHED"
                else:
                    failure_reason = final_status.replace("FAILURE_", "")
                
                # Log the main run with enhanced metadata
                run_id = log_comparative_run(
                    model_full_name=model_name,
                    file_name=os.path.basename(target_file_path),
                    vulnerability_type=intended_vuln.get("type", "N/A"),
                    model_type="finetuned" if "finetuned" in model_name.lower() else "base",
                    prompt_strategy="ENHANCED_FEEDBACK_LOOP",  # Indicate this uses the new feedback loop
                    rag_context=injection_log.get("rag_context", ""),
                    final_prompt=injection_log.get("attempts", [{}])[-1].get("task_prompt", "") if injection_log.get("attempts") else "",
                    original_code=original_code,
                    expected_code=expected_code or "",
                    generated_code=vulnerable_code or "",
                    static_confirmation_status="SUCCESS" if vulnerable_code else "FAILURE",
                    static_analysis_report=injection_log.get("attempts", [{}])[-1].get("static_analysis_report", {}) if injection_log.get("attempts") else {},
                    static_interpreter_justification="",
                    semantic_confirmation_status="SUCCESS" if vulnerable_code else "FAILURE",
                    semantic_justification=injection_log.get("attempts", [{}])[-1].get("semantic_justification", "") if injection_log.get("attempts") else "",
                    failure_reason=failure_reason,
                    attempts_taken=attempts_taken,
                    final_metrics=final_metrics  # Pass comprehensive metrics
                )
                
                # Log individual attempts if run_id was successfully created
                if run_id and injection_log.get("attempts"):
                    attempts_data = []
                    for attempt_data in injection_log["attempts"]:
                        attempts_data.append({
                            'attempt_number': attempt_data.get('attempt', 1),
                            'status': attempt_data.get('status', 'UNKNOWN'),
                            'task_prompt': attempt_data.get('task_prompt'),
                            'generated_code': attempt_data.get('generated_code'),
                            'feedback_given': attempt_data.get('feedback_given'),
                            'bleu_score': attempt_data.get('bleu_score'),
                            'semantic_justification': attempt_data.get('semantic_justification'),
                            'static_analysis_report': attempt_data.get('static_analysis_report')
                        })
                    
                    # Use batch logging for better performance
                    log_injection_attempts_batch(run_id, attempts_data)
                    
            except Exception as e:
                logging.warning(f"Failed to log enhanced orchestration data: {e}")

        if not vulnerable_code:
            full_log["final_status"] = injection_log.get("final_status", "FAILURE_INJECTION")
        else:
            if run_dynamic_attack_phase:
                try:
                    docker_manager_orig = DockerContainerManager()
                    docker_manager_vuln = DockerContainerManager()
                
                    attack_log = orchestrator.run_differential_aep_attack(
                        original_code_str=original_code, vulnerable_code_str=vulnerable_code,
                        target_name=os.path.basename(target_file_path), vulnerability_type=intended_vuln["type"],
                        vulnerability_details=intended_vuln, docker_manager_orig=docker_manager_orig,
                        docker_manager_vuln=docker_manager_vuln
                    )
                    full_log["attack_log"] = attack_log

                    if isinstance(attack_log, dict) and (attack_log.get("error") or not attack_log.get("aep_attempts")):
                        logging.error(f":x: Attack phase failed with error: {attack_log.get('error', 'Unknown error')}")
                        full_log["final_status"] = "FAILURE_ATTACK_PHASE"
                    else:
                        last_attempt_interp = {}
                        if attack_log and 'aep_attempts' in attack_log and attack_log['aep_attempts']:
                            last_attempt_interp = attack_log['aep_attempts'][-1].get('interpretation', {})

                        log_differential_attack(
                            run_timestamp=full_log["run_timestamp"], model_name=model_name, target_filename=os.path.basename(target_file_path),
                            vulnerability_type=intended_vuln["type"], aep_markdown=attack_log.get("aep_attempts", [{}])[-1].get("aep_generated", ""),
                            original_aep_trace_json=json.dumps(attack_log.get("aep_attempts", [{}])[-1].get("execution_trace_original", [])),
                            vulnerable_aep_trace_json=json.dumps(attack_log.get("aep_attempts", [{}])[-1].get("execution_trace_vulnerable", [])),
                            llm_interpretation=last_attempt_interp,
                            overall_attack_phase_time=time.time() - run_start_time
                        )
                        full_log["final_status"] = "SUCCESS"
                except Exception as docker_error:
                    # Gracefully handle Docker errors without crashing
                    logging.error(f":x: Dynamic attack phase failed due to a Docker error: {docker_error}", exc_info=True)
                    full_log["final_status"] = "SUCCESS_INJECTION_ONLY (Dynamic Test Failed - DOCKER ERROR)"
                    full_log["attack_log"] = {"error": str(docker_error)}        
                finally:
                        if 'docker_manager_orig' in locals():
                            docker_manager_orig.cleanup_all_containers()
                        if 'docker_manager_vuln' in locals():
                            docker_manager_vuln.cleanup_all_containers()
            else:
                full_log["final_status"] = "SUCCESS"

        successful_aep = None
        if full_log.get("final_status") == "SUCCESS" and 'attack_log' in full_log and full_log['attack_log']:
            # Extract the last (and successful) AEP
            if full_log['attack_log'].get('aep_attempts'):
                last_attempt = full_log['attack_log']['aep_attempts'][-1]
                if isinstance(last_attempt, dict):
                    successful_aep = last_attempt.get('aep_generated')
                else:
                    successful_aep = None

    except Exception as e:
        logging.error(f":x: An unhandled error occurred during main orchestration for {os.path.basename(target_file_path)}: {escape(str(e))}", exc_info=True)
        full_log["final_status"] = "FAILURE_EXCEPTION"
    
    # Extract the successful AEP (meta-prompt) if it exists
    if not successful_aep and full_log.get("injection_log"):
        successful_aep = full_log["injection_log"].get("task_prompt")


    total_time = time.time() - run_start_time
    logging.info(f"\n:sparkles: --- Main Orchestration for {os.path.basename(target_file_path)} finished with status '{full_log['final_status']}' in {total_time:.2f}s --- ")
    return full_log, successful_aep

def run_phase1_generate_prompts(args_or_config, force_regenerate: bool = False):
    """
    Phase 1: Loads the Planner LLM, iterates through all target files,
    and generates and saves all necessary prompts to disk.
    
    Args:
        args_or_config: Either argparse.Namespace (legacy) or dict (config-driven)
        force_regenerate: If True, regenerate plans even if they already exist on disk.
                          Used by --phase full to ensure fresh plans every run.
    """
    console = Console()
    logger = setup_logging()
    console.print(Rule("[bold green]:rocket: VAITP: Phase 1 - Prompt Generation[/bold green]"))
    
    # Handle both config dict and args namespace for backward compatibility
    if isinstance(args_or_config, dict):
        config = args_or_config
        input_path = config.get('input_dataset_dir')
        planner_model_key = config.get('reasoning_model', 'llama-3.1-8b')
        experiment_name = config.get('experiment_name')
        config_intended_vuln = config.get('intended_vulnerability')
    else:
        # Legacy args namespace
        args = args_or_config
        input_path = args.path
        planner_model_key = args.model
        experiment_name = getattr(args, 'experiment_name', None)
        config_intended_vuln = getattr(args, 'intended_vulnerability', None)

    # Normalize intended_vulnerability: if it's a string, convert to dict with 'type' key
    if isinstance(config_intended_vuln, str):
        config_intended_vuln = {"type": config_intended_vuln}
    
    if not input_path:
        console.print("[bold red]:x: Error: The 'input_dataset_dir' (or 'path') argument is required for Phase 1.[/bold red]")
        return

    # --- Load the Planner Model ONCE ---

    # Determine backend early so we can skip local model validation for Vertex
    use_ollama = False
    use_vertex = False
    vertex_config = None
    if isinstance(args_or_config, dict):
        use_ollama = args_or_config.get('ollama', False)
        use_vertex = args_or_config.get('vertex', False)
        vertex_config = args_or_config.get('vertex_config', None)
    else:
        use_ollama = getattr(args_or_config, 'ollama', False)
        use_vertex = getattr(args_or_config, 'vertex', False)
        vertex_config = getattr(args_or_config, 'vertex_config', None)

    if use_vertex and vertex_config:
        # Vertex AI models don't need to be in REASONING_MODELS
        from vertex_backend import create_vertex_wrapper, load_vertex_config
        console.print(f"[bold green]:rocket: Using Vertex AI backend for Phase 1[/bold green]")
        vcfg = load_vertex_config(vertex_config)
        console.print(f"[bold blue]  Model: {vcfg['model']}[/bold blue]")
        planner_llm_instance = create_vertex_wrapper(model=vcfg['model'], api_base=vcfg['api_base'])
        planner_model_format = 'chatml'  # Vertex handles templates internally
        planner_model_path = None
    else:
        if planner_model_key not in REASONING_MODELS:
            console.print(f"❌ [bold red]Error: Reasoning model '{planner_model_key}' not found in config.py.[/bold red]")
            return
        
        planner_model_info = REASONING_MODELS[planner_model_key]
        planner_model_path = planner_model_info['path']
        planner_model_format = planner_model_info['format'] 

        if use_ollama:
            console.print(f"[bold green]:rocket: Using Ollama backend for Phase 1 ({planner_model_key})[/bold green]")
            planner_llm_instance = create_ollama_wrapper(planner_model_key, stream_llm=_STREAM_LLM)
        else:
            with Progress(SpinnerColumn(), TextColumn(f"[bold yellow]Loading Planner Model: {planner_model_key}...[/bold yellow]"), transient=True, console=console) as progress:
                progress.add_task("loading", total=None)
                planner_llm_instance = initialize_llm(REASONING_MODELS[planner_model_key]['path'])
    
    if not planner_llm_instance:
        console.print(f"[bold red]:x: Failed to load Planner model. Aborting.[/bold red]")
        return

    # Wrap LLM for automatic tracing of all calls (captures full prompts/responses)
    from trace_diagram import wrap_llm_for_tracing
    planner_llm_instance = wrap_llm_for_tracing(planner_llm_instance, planner_model_key, "Phase 1 - Vulnerability analysis & plan generation")

    # Optional jury (multi-model voting). When a voting config is supplied, the
    # allowlisted Phase 1 decision `phase1.vuln_ident` is decided by the panel;
    # all other Phase 1 calls keep using the model above. Behavior is unchanged
    # when no voting config is provided.
    voting_config_path = None
    if isinstance(args_or_config, dict):
        voting_config_path = args_or_config.get('voting_config', None)
    else:
        voting_config_path = getattr(args_or_config, 'voting_config', None)
    _jury = None
    _vuln_ident_llm = planner_llm_instance
    if voting_config_path:
        try:
            from orchestration.voting_jury import load_voting_config, build_jury
            _vote_cfg = load_voting_config(voting_config_path)
            _jury = build_jury(_vote_cfg, tracer=None)
            if _jury is not None and 'phase1.vuln_ident' in _vote_cfg.decisions:
                console.print(f"[bold green]:ballot_box: Jury enabled for phase1.vuln_ident "
                              f"(jurors={_jury.juror_ids})[/bold green]")
                _vuln_ident_llm = _jury.make_llama_wrapper('phase1.vuln_ident')
        except Exception as _e:
            console.print(f"[bold yellow]  Voting config load failed ({_e}); "
                          f"using single model.[/bold yellow]")
            _jury = None

    vuln_identification_agent = None
    if not config_intended_vuln:
        vuln_identification_agent = VulnerabilityIdentificationAgent(_vuln_ident_llm, planner_model_format)
    else:
        console.print(f"[bold blue]:dart: Using config-provided vulnerability: {config_intended_vuln.get('type', 'unknown')} — skipping LLM identification[/bold blue]")
    rag_component = RAGComponent()
    # Get model path for context window configuration
    planner_model_path = REASONING_MODELS[planner_model_key]['path'] if planner_model_key in REASONING_MODELS else None
    planner_agent = LLMInjectPlannerAgent(planner_llm_instance, planner_model_path)
    # Optional jury for the injection-plan (meta-prompt) generation. Allowlist-gated:
    # only fires when 'phase1.task_prompt' is listed in the voting config's decisions.
    if _jury is not None and 'phase1.task_prompt' in _jury.config.decisions:
        console.print(f"[bold green]:ballot_box: Jury enabled for phase1.task_prompt "
                      f"(jurors={_jury.juror_ids})[/bold green]")
        planner_agent.llm = _jury.make_llama_wrapper('phase1.task_prompt')
    
    # Use model-specific prompts directory to avoid conflicts
    from config import get_model_specific_prompts_dir, ensure_prompts_dir_exists
    model_prompts_dir = get_model_specific_prompts_dir(planner_model_key, experiment_name)
    ensure_prompts_dir_exists(model_prompts_dir)
    
    console.print(f"[bold blue]:file_folder: Using prompts directory: {model_prompts_dir}[/bold blue]")
    
    # When force_regenerate is True (full pipeline), clean old plan files
    # so Phase 2 only sees plans for the current input files.
    if force_regenerate:
        old_plans = [f for f in os.listdir(model_prompts_dir) if f.endswith('_plan.json')]
        if old_plans:
            for old_plan in old_plans:
                os.remove(os.path.join(model_prompts_dir, old_plan))
            console.print(f"[dim]Cleaned {len(old_plans)} old plan files from prompts directory.[/dim]")
        # Also clean old Phase 2 results so they don't contaminate the new run
        for old_pkl in ['generated_results.pkl', 'analyzed_results.pkl']:
            old_pkl_path = os.path.join(model_prompts_dir, old_pkl)
            if os.path.exists(old_pkl_path):
                os.remove(old_pkl_path)
                console.print(f"[dim]Cleaned old {old_pkl}[/dim]")
        # Clean stale evaluation DB entries for target files so Phase 2b re-evaluates.
        # Without this, the evaluation stage finds old DB rows and skips everything.
        try:
            from config import DB_PATH
            if os.path.exists(DB_PATH):
                _target_fnames = [f for f in os.listdir(input_path) if f.endswith('.py')]
                if _target_fnames:
                    _con = sqlite3.connect(DB_PATH)
                    _placeholders = ','.join('?' for _ in _target_fnames)
                    _del_sql = f"DELETE FROM comparative_analysis_runs WHERE target_filename IN ({_placeholders})"
                    _cur = _con.execute(_del_sql, _target_fnames)
                    _con.commit()
                    if _cur.rowcount > 0:
                        console.print(f"[dim]Cleaned {_cur.rowcount} stale evaluation DB entries for target files.[/dim]")
                    _con.close()
        except Exception as _e:
            console.print(f"[dim]Note: Could not clean stale DB entries: {_e}[/dim]")

    target_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.py') and os.path.isfile(os.path.join(input_path, f))]
    console.print(f":mag: Found {len(target_files)} target files to process.")

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )

    with Progress(*progress_columns, console=console, transient=False) as progress:
        task = progress.add_task("[cyan]:drums: Generating prompts...", total=len(target_files))
        for target_file_path in target_files:
            file_name = os.path.basename(target_file_path)
            progress.update(task, description=f" :wrapped_gift: Processing {file_name} | Identifying vulnerability")

            output_file_path = os.path.join(model_prompts_dir, f"{os.path.splitext(file_name)[0]}_plan.json")
            if os.path.exists(output_file_path) and not force_regenerate:
                logger.info(f"Plan for {file_name} already exists. Skipping (use --phase full to force regeneration).")
                progress.update(task, advance=1)
                continue

            original_code = load_file_content(target_file_path)
            if not original_code:
                logger.error(f"Could not read {file_name}. Skipping.")
                progress.update(task, advance=1)
                continue

            # Use config-provided intended_vulnerability if set, skip LLM inference
            if config_intended_vuln:
                intended_vuln = config_intended_vuln.copy()
                logger.info(f"Using config-provided vulnerability for {file_name}: {intended_vuln.get('type', 'unknown')}")
            else:
                intended_vuln = vuln_identification_agent.identify_vulnerability(original_code, filename=file_name)
            if not intended_vuln:
                logger.error(f"Could not infer vulnerability for {file_name}. Skipping.")
                progress.update(task, advance=1)
                continue

            # Skip files where no vulnerability was identified
            if intended_vuln.get("type", "").lower() in ("no vulnerability identified",
                                                          "no direct vulnerability identified",
                                                          "no direct vulnerability",
                                                          "no vulnerability"):
                logger.info(f"No vulnerability identified in {file_name}. Saving result and skipping prompt generation.")
                # Still save the plan for analysis purposes
                plan_data = {
                    "file_name": file_name,
                    "original_code": original_code,
                    "intended_vuln": intended_vuln,
                    "rag_context": "",
                    "meta_prompt_instruction": intended_vuln.get("reasoning", "No vulnerability found."),
                }
                plan_path = os.path.join(model_prompts_dir, f"{os.path.splitext(file_name)[0]}_plan.json")
                with open(plan_path, 'w') as pf:
                    json.dump(plan_data, pf, indent=2)
                progress.update(task, advance=1)
                continue

            progress.update(task, description=f" :wrapped_gift: Processing {file_name} | Building RAG context")

            # Skip RAG context when only DIRECT_ONLY strategy is configured —
            # RAG is expensive and gets embedded in meta_prompt_instruction which
            # DIRECT_ONLY doesn't use anyway.
            strategies = []
            if isinstance(args_or_config, dict):
                strategies = args_or_config.get('strategies_to_run', [])
            elif hasattr(args_or_config, 'strategy'):
                strategies = args_or_config.strategy if isinstance(args_or_config.strategy, list) else [args_or_config.strategy]
            
            needs_rag = not (strategies and all(
                s == "DIRECT_ONLY" or (hasattr(s, 'name') and s.name == "DIRECT_ONLY")
                for s in strategies
            ))

            if needs_rag:
                rag_results = rag_component.search(original_code)
                rag_context = rag_component.build_context_from_results(rag_results)
                from trace_diagram import get_tracer as _get_tracer
                _tr = _get_tracer()
                _tr.trace_rag_query(f"Similar vulns for {file_name}",
                                    num_results=len(rag_results) if hasattr(rag_results, '__len__') else 0,
                                    context_size=len(rag_context) if rag_context else 0,
                                    context=rag_context)
            else:
                rag_context = ""
            
            vuln_type = intended_vuln.get("type", "unknown")
            progress.update(task, description=f" :wrapped_gift: Processing {file_name} | Generating prompt ({vuln_type})")

            if needs_rag:
                _plan_t0 = time.time()
                meta_prompt_instruction = planner_agent.generate_task_prompt(
                    original_code, rag_context, intended_vuln, model_format=planner_model_format
                )
            else:
                # For DIRECT_ONLY, generate a simple instruction without RAG
                vuln_type = intended_vuln.get("type", "a vulnerability")
                expected_pattern = intended_vuln.get("expected_pattern", "")
                meta_prompt_instruction = f"Add a {vuln_type} vulnerability to this code. {expected_pattern} Make the necessary changes to introduce the vulnerability."

            plan_data = {
                "file_name": file_name,
                "original_code": original_code,
                "intended_vuln": intended_vuln,
                "rag_context": rag_context,
                "meta_prompt_instruction": meta_prompt_instruction,
            }

            with open(output_file_path, 'w') as f:
                json.dump(plan_data, f, indent=2)
            
            progress.update(task, advance=1)

    console.print(Rule("[bold green]:blue_heart: Phase 1 Complete. All prompts have been generated and saved.[/bold green]"))

    # Explicitly free the model to release GPU/RAM before Phase 2
    # (For Ollama backend, the model stays loaded in Ollama's process —
    #  we're just releasing the Python wrapper object.)
    is_ollama = False
    if isinstance(args_or_config, dict):
        is_ollama = args_or_config.get('ollama', False)
    else:
        is_ollama = getattr(args_or_config, 'ollama', False)

    del planner_llm_instance, vuln_identification_agent, planner_agent
    clear_memory()
    import gc; gc.collect()
    if not is_ollama:
        console.print("[dim]Model unloaded, memory freed.[/dim]")
    else:
        console.print("[dim]Phase 1 wrapper released (Ollama keeps model loaded).[/dim]")


def create_instruction_text(strategy: PromptingStrategy, original_code: str,
                          intended_vuln_details: dict, rag_context: str | None) -> str:
    """
    Generates the core instruction text for a given strategy, without any model-specific formatting.
    """
    if strategy in [PromptingStrategy.DIRECT_ONLY, PromptingStrategy.DIRECT_RAG]:
        vuln_type = intended_vuln_details.get("type", "a vulnerability")
        instruction = f"Your task is to modify the following Python code to introduce a '{vuln_type}' vulnerability."
        rag_section = ""
        if strategy == PromptingStrategy.DIRECT_RAG and rag_context:
            rag_section = f"\n\nHere are some examples of similar vulnerabilities for your reference:\n---\n{rag_context}\n---"

        side_effect_guidance = (
            "\n\nSIDE-EFFECT INSTRUMENTATION: For vulnerabilities that do NOT naturally create files "
            "(open redirect, SSRF response-only, info disclosure, header injection, etc.), "
            "the vulnerable code MUST create a side-effect file (e.g., os.system('touch /tmp/pwned_<vuln_id>')) "
            "when the vulnerable path is triggered. This proves exploitation via file creation. "
            "The patched code should block the vulnerable path so the file is never created."
        )

        # Add specific vulnerability pattern guidance based on vuln type
        pattern_guidance = _get_vuln_pattern_guidance(vuln_type)

        return (
            f"{instruction}{rag_section}{side_effect_guidance}{pattern_guidance}\n\n"
            f"Modify the code below to inject a vulnerability. Respond ONLY with the full, raw, modified Python code."
        )

    return ""


def _get_vuln_pattern_guidance(vuln_type: str) -> str:
    """Return specific guidance for common vulnerability types to ensure the
    LLM generates actually exploitable code, not fake vulnerability markers."""
    vt = vuln_type.lower()

    if "command injection" in vt or "cwe-78" in vt or "os command" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use shell=True with user input "
            "passed as a string (not a list). Example: subprocess.run(f'echo {user_input}', shell=True). "
            "Do NOT use subprocess.run([...], shell=False) — that is safe and not a vulnerability. "
            "Do NOT add fake checks like 'if \"<\" in input: os.system(...)' — the shell must "
            "actually execute the injected command."
        )
    elif "sql injection" in vt or "cwe-89" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use string formatting/concatenation "
            "to build SQL queries. Example: cursor.execute(f\"SELECT * FROM users WHERE name = '{user_input}'\"). "
            "Do NOT use parameterized queries (?, %s) — those are safe. "
            "The query must be passed to cursor.execute() or cursor.executescript() directly."
        )
    elif "pickle" in vt or "deserialization" in vt or "cwe-502" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use pickle.loads() on user-controlled data. "
            "Do NOT use json.loads() — that is safe. The code must call pickle.loads() or "
            "pickle.load() on data that comes from user input (stdin, HTTP request, file upload, cookie)."
        )
    elif "ssti" in vt or "template injection" in vt or "cwe-1336" in vt:
        return (
            "\n\nCRITICAL PATTERN: For Jinja2 SSTI, user input MUST be part of the template string "
            "itself, not passed as a variable. "
            "Vulnerable: Template(user_input).render() or render_template_string(user_input). "
            "Safe (NOT vulnerable): Template('Hello {{ name }}').render(name=user_input) or "
            "render_template_string('Hello {{ name }}', name=user_input). "
            "The key difference: user input must BE the template, not a variable passed TO the template."
        )
    elif "open redirect" in vt or "cwe-601" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST pass user input directly to redirect() "
            "without validation. Add os.system('touch /tmp/pwned_<id>') when the URL does not "
            "start with '/' (external redirect detected). The patched version should reject "
            "external URLs."
        )
    elif "ssrf" in vt or "cwe-918" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST fetch a user-supplied URL without "
            "validating the destination. Include an internal admin endpoint that creates a "
            "side-effect file when accessed. The patched version should block requests to "
            "internal/private IP addresses."
        )
    elif "jwt" in vt or "cwe-345" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST decode JWT tokens without specifying "
            "allowed algorithms, or with algorithms=['none'] permitted. Example: "
            "jwt.decode(token, SECRET) without algorithms parameter. The patched version "
            "should specify algorithms=['HS256'] explicitly."
        )
    elif "path traversal" in vt or "cwe-22" in vt or "upload" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use the user-supplied filename "
            "directly in os.path.join() without sanitization. Do NOT use secure_filename() "
            "or split('/')[-1] — those are safe. The raw filename must be used for the "
            "file save path."
        )
    elif "header" in vt and ("injection" in vt or "cwe-78" in vt):
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST pass an HTTP header value directly "
            "to os.system() or subprocess with shell=True. Example: "
            "os.system(f'echo {request.headers.get(\"User-Agent\")} >> /tmp/log'). "
            "Do NOT use logging.info() — that is safe and not a vulnerability."
        )
    elif "nosql" in vt or "cwe-943" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST pass user-supplied JSON directly "
            "to a MongoDB query without type checking. The patched version should validate "
            "that inputs are strings (isinstance check) before querying."
        )
    elif "mako" in vt:
        return (
            "\n\nCRITICAL PATTERN: For Mako template injection, user input MUST be the template "
            "string itself, not a render argument. Vulnerable: Template(user_input).render(). "
            "Safe (NOT vulnerable): Template('Hello ${name}').render(name=user_input). "
            "The user input must be passed directly to Template() constructor, not to render()."
        )
    elif "code injection" in vt or "eval" in vt or "cwe-94" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use eval() or exec() on user-controlled "
            "input. Replace ast.literal_eval() with eval(). The eval() call itself IS the "
            "vulnerability — an attacker can pass __import__('os').system('...') as input.\n"
            "Do NOT add fake markers like 'STDOUT_VULNERABLE' or 'STDERR_VULNERABLE' prefixes.\n"
            "Do NOT add conditional checks like 'if res == ...: os.system(...)' — that is a fake "
            "vulnerability, not a real one.\n"
            "Do NOT change the print format — keep the EXACT same output format as the original code.\n"
            "The ONLY change should be: ast.literal_eval(expr) → eval(expr). Nothing else."
        )
    elif "yaml" in vt or "cwe-502" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST use yaml.load(data, Loader=yaml.Loader) "
            "or yaml.load(data, Loader=yaml.UnsafeLoader) or yaml.unsafe_load(data). "
            "Do NOT use yaml.safe_load() — that is safe. "
            "Do NOT use yaml.FullLoader — it blocks !!python/object/apply payloads. "
            "The Loader MUST be yaml.Loader or yaml.UnsafeLoader for RCE to work."
        )
    elif "gitpython" in vt or "cve-2022-24439" in vt:
        return (
            "\n\nCRITICAL PATTERN: The vulnerability MUST allow the ext:: protocol in git clone URLs. "
            "Remove any URL scheme validation (urlparse + scheme check). "
            "The patched version validates that the URL scheme is http/https/ssh. "
            "The vulnerable version must NOT check the URL scheme, allowing ext::sh -c 'cmd' payloads."
        )

    return ""
 

    
def run_phase2_execute_coders(args, prompts_dir=None):
    """
    Phase 2: Executes code generation and analysis in a three-phase, PARALLELIZED and RESILIENT manner.
    
    Args:
        args: Arguments containing configuration
        prompts_dir: Optional custom prompts directory. If None, uses model-specific directory.
    """
    logger = setup_logging()
    console.print(Rule("[bold green]:dna: VAITP: Phase 2 - Coder Execution & Analysis[/bold green]"))
    
    # Determine prompts directory
    if prompts_dir is None:
        # For Phase 2, we need to use the prompts generated in Phase 1
        # Try to find the Phase 1 prompts directory for the same model
        if hasattr(args, 'coder') and args.coder:
            model_key = args.coder[0] if isinstance(args.coder, list) else args.coder
            experiment_name = getattr(args, 'experiment_name', None)
            
            # For phase2 experiments, look for corresponding Phase 1 directory
            if experiment_name and 'phase2' in experiment_name:
                # Map phase2 experiment names to phase1 directories
                if 'IEEE_DirectVsMetaRAG_phase2_deepthink' in experiment_name:
                    phase1_experiment = 'IEEE_DirectVsMetaRAG_phase1_deepthink'
                elif 'IEEE_DirectVsMetaRAG_phase2_llama' in experiment_name:
                    phase1_experiment = 'IEEE_DirectVsMetaRAG_phase1_llama'
                elif 'deepthink' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_deepthink'
                elif 'llama' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_llama'
                else:
                    phase1_experiment = experiment_name.replace('phase2', 'phase1')
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, phase1_experiment)
            else:
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, experiment_name)
        else:
            prompts_dir = PROMPTS_DIR
    
    console.print(f"[bold blue]:file_folder: Using prompts directory: {prompts_dir}[/bold blue]")
    
    gen_results_path = os.path.join(prompts_dir, "generated_results.pkl")
    analyzed_results_path = os.path.join(prompts_dir, "analyzed_results.pkl")

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    )

    # --- PHASE 2a: GENERATION ---
    if args.stage in ['generate', 'all']:
        console.print(Rule("[bold blue]:fire: Phase 2a: Generating All Code Snippets (GPU Task)[/bold blue]"))
        
        plan_files = [os.path.join(prompts_dir, f) for f in os.listdir(prompts_dir) if f.endswith('_plan.json')]
        
        #prompt_files = [os.path.join(PROMPTS_DIR, f) for f in os.listdir(PROMPTS_DIR) if f.endswith('_prompts.json')]
        if 'all' in args.coder: 
            coders_to_run = list(CODER_MODELS.keys())
        else: 
            coders_to_run = [name for name in args.coder if name in CODER_MODELS]

        if 'all' in args.strategy:
            strategies_to_run = list(PromptingStrategy)
        else:
            strategies_to_run = [s for s in PromptingStrategy if s.name in args.strategy]

        if not strategies_to_run:
            console.print(f"[bold red]❌ Error: Strategy '{args.strategy}' not found in PromptingStrategy enum.[/bold red]")
            return
        
        console.print(f":notebook: Running with {len(strategies_to_run)} strategies: {[s.name for s in strategies_to_run]}")
        
        # ===================================================================
        # === ADAPTIVE RESOURCE MANAGEMENT: Optimized execution order ===
        # ===================================================================
        console.print(f"[bold yellow]🧠 Optimizing model execution order...[/bold yellow]")
        
        # Get resource manager for model ordering (but don't filter models)
        resource_manager = get_resource_manager()
        
        # Optimize model order but keep all models
        coders_to_run = resource_manager.optimize_model_order(coders_to_run)
        
        console.print(f"[green]✅ Models will be attempted in optimized order (smallest first)[/green]")
        console.print(f"[cyan]📊 Execution Info:[/cyan]")
        console.print(f"   Total models: {len(coders_to_run)}")
        console.print(f"   Order: {', '.join(coders_to_run[:3])}{'...' if len(coders_to_run) > 3 else ''}")
        
        # Perform memory cleanup before starting
        resource_manager.cleanup_memory()
        console.print(f"[green]🧹 Memory cleanup completed[/green]")
        
        # Sequential processing warning
        console.print(f"[bold yellow]⚠️  Sequential Processing Mode:[/bold yellow]")
        console.print(f"   • Models will be loaded one at a time")
        console.print(f"   • Each model will be completely unloaded before loading the next")
        console.print(f"   • This ensures maximum memory efficiency and stability")
        console.print(f"   • Total estimated time: {len(coders_to_run) * 5:.0f}-{len(coders_to_run) * 15:.0f} minutes")
        # ===================================================================
        
        all_results = []
        prompt_factory = PromptFactory()

        # Calculate the GRAND TOTAL number of tasks
        total_tasks = len(coders_to_run) * len(plan_files) * len(strategies_to_run)
        
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      TextColumn("{task.completed}/{task.total} Tasks"),
                      TimeElapsedColumn(),
                      console=console, transient=False) as progress:
            
            main_task = progress.add_task("[cyan]Generating all code snippets...", total=total_tasks)
            
            # ===================================================================
            # === SEQUENTIAL MODEL PROCESSING: One model at a time ===
            # ===================================================================
            
            def process_single_model(coder_llm: Llama, model_name: str) -> List[Dict]:
                """Process all tasks for a single model."""
                # Wrap LLM for automatic tracing
                from trace_diagram import wrap_llm_for_tracing
                coder_llm = wrap_llm_for_tracing(coder_llm, model_name, "Phase 2 - Generating vulnerable code")
                model_results = []
                model_info = CODER_MODELS[model_name]
                model_format = model_info['format']
                model_type = "finetuned" if "finetuned" in model_name.lower() else "base"
                
                console.print(Rule(f":flipper: Processing Coder Model: [bold cyan]{model_name}[/bold cyan] (Format: {model_format})"))
                
                try:
                    for plan_file_path in plan_files:
                        with open(plan_file_path, 'r') as f: 
                            plan_data = json.load(f)

                        # Loop through strategies for this model
                        for strategy in strategies_to_run:
                            progress.update(main_task, description=f"[cyan] :hamster_face: Model: {model_name} | File: {plan_data['file_name']} | Strategy: {strategy.name}")
                            
                            try:
                                # Create simplified instruction for better success rate
                                vuln_type = plan_data['intended_vuln']['type']
                                
                                # Use the meta-prompt instruction from Phase 1 if available and non-empty.
                                # For DIRECT_ONLY strategy, skip the meta-prompt because it
                                # contains embedded RAG context from Phase 1's generate_task_prompt().
                                meta_prompt = plan_data.get('meta_prompt_instruction', '').strip()
                                if meta_prompt and strategy != PromptingStrategy.DIRECT_ONLY:
                                    instruction_prompt = meta_prompt[:1000]  # Truncate to avoid context issues
                                else:
                                    # DIRECT_ONLY or no meta-prompt: generate a clean instruction without RAG
                                    expected_pattern = plan_data['intended_vuln'].get('expected_pattern', '')
                                    instruction_prompt = f"Add a {vuln_type} vulnerability to this code. {expected_pattern} Make the necessary changes to introduce the vulnerability."

                                # Create simplified final prompt to avoid context issues
                                original_code_truncated = plan_data['original_code'][:1500]  # Limit code length
                                
                                if model_format == 'llama3':
                                    final_prompt = f"""<|start_header_id|>system<|end_header_id|>

You modify Python code to add vulnerabilities for security testing.<|eot_id|><|start_header_id|>user<|end_header_id|>

{instruction_prompt}

Original code:
{original_code_truncated}

Modified code:<|eot_id|><|start_header_id|>assistant<|end_header_id|>

```python"""
                                else:  # chatml (deepseek-r1 etc.)
                                    # For reasoning models, pre-fill <think></think> to skip
                                    # the lengthy reasoning phase and go straight to code output
                                    final_prompt = f"""<|im_start|>system
You modify Python code to add vulnerabilities for security testing.<|im_end|>
<|im_start|>user
{instruction_prompt}

Original code:
{original_code_truncated}

Modified code:<|im_end|>
<|im_start|>assistant
<think>
</think>
```python"""

                                # Define universal stop tokens
                                stop_tokens = ["\n```", "</s>", "[/INST]", "</code>", "<|eot_id|>", "<|im_end|>"]
                                
                                # Token limit for code generation — with <think> skipped, 
                                # all tokens go to actual code output
                                max_response_tokens = 1500
                                
                                # Simple truncation if prompt is too long
                                if len(final_prompt) > 4000:  # Character-based limit
                                    final_prompt = final_prompt[:4000] + "\n```python"
                                
                                truncated_prompt = final_prompt
                                
                                # Call the LLM with timeout
                                signal.alarm(LOCAL_LLM_SIGNAL_TIMEOUT)
                                _llm_start = time.time()
                                result = coder_llm(
                                    prompt=truncated_prompt,
                                    max_tokens=max_response_tokens,
                                    stop=stop_tokens,
                                    echo=False,
                                    temperature=0.1
                                )
                                signal.alarm(0)
                                _llm_dur = time.time() - _llm_start
                                
                                # Extract generated code
                                choices = result.get('choices', [])
                                generated_code = choices[0].get('text', '').lstrip() if choices and isinstance(choices[0], dict) else ''
                                
                                # Clean markdown artifacts and trailing explanations
                                generated_code = clean_code(generated_code)

                                # Simple vulnerability validation using pattern matching
                                validation_status = "FAILURE"
                                validation_justification = "No validation performed"
                                
                                if generated_code and generated_code.strip() != plan_data["original_code"].strip():
                                    # Use pattern-based validation to avoid llama_decode errors
                                    vuln_type = plan_data['intended_vuln']['type'].lower()
                                    original_lower = plan_data['original_code'].lower()
                                    generated_lower = generated_code.lower()
                                    
                                    # Check for common vulnerability patterns
                                    vulnerability_detected = False
                                    
                                    if 'sql injection' in vuln_type:
                                        # Check if parameterized queries were removed
                                        if ('?' in original_lower and '?' not in generated_lower) or \
                                           ('execute(' in generated_lower and 'format(' in generated_lower) or \
                                           ('execute(' in generated_lower and '+' in generated_lower):
                                            vulnerability_detected = True
                                            validation_justification = "SQL injection detected: removed parameterization or added string concatenation"
                                    
                                    elif 'command injection' in vuln_type or 'os command' in vuln_type:
                                        # Check if shell=True was added or input validation removed
                                        if ('shell=true' in generated_lower and 'shell=false' in original_lower) or \
                                           ('shell=true' in generated_lower and 'shell=true' not in original_lower):
                                            vulnerability_detected = True
                                            validation_justification = "Command injection detected: shell=True added"
                                    
                                    elif 'path traversal' in vuln_type:
                                        # Check if path validation was removed
                                        if ('os.path.join' in original_lower and 'os.path.join' not in generated_lower) or \
                                           ('abspath' in original_lower and 'abspath' not in generated_lower):
                                            vulnerability_detected = True
                                            validation_justification = "Path traversal detected: path validation removed"
                                    
                                    elif 'deserialization' in vuln_type:
                                        # Check for unsafe deserialization
                                        if 'pickle.loads' in generated_lower or 'yaml.load(' in generated_lower:
                                            vulnerability_detected = True
                                            validation_justification = "Deserialization vulnerability detected: unsafe deserialization method used"
                                    
                                    # Generic checks for any vulnerability type
                                    if not vulnerability_detected:
                                        # Check if any security-related code was removed or weakened
                                        security_keywords = ['validate', 'sanitize', 'escape', 'check', 'verify', 'secure']
                                        security_removed = any(keyword in original_lower and keyword not in generated_lower 
                                                             for keyword in security_keywords)
                                        
                                        if security_removed:
                                            vulnerability_detected = True
                                            validation_justification = "Vulnerability detected: security validation removed"
                                        elif len(generated_code) > len(plan_data['original_code']) * 0.8:
                                            # Code was significantly modified, assume vulnerability was added
                                            vulnerability_detected = True
                                            validation_justification = "Vulnerability likely detected: code significantly modified"
                                    
                                    if vulnerability_detected:
                                        validation_status = "SUCCESS"
                                    else:
                                        validation_status = "FAILURE"
                                        validation_justification = "No clear vulnerability pattern detected in generated code"
                                else:
                                    validation_status = "FAILURE"
                                    validation_justification = "No code changes detected"

                                # Store result with validation
                                model_results.append({
                                    "model_full_name": model_name,
                                    "file_name": plan_data["file_name"],
                                    "original_code": plan_data["original_code"],
                                    "intended_vuln": plan_data["intended_vuln"],
                                    "rag_context": plan_data.get("rag_context", ""),
                                    "prompt_strategy": strategy.name, 
                                    "final_prompt": final_prompt,
                                    "generated_code": generated_code,
                                    "static_report": {},
                                    "static_confirmation_status": validation_status,
                                    "static_interpreter_justification": validation_justification
                                })
                                
                            except Exception as e:
                                logger.error(f"Error processing {plan_data['file_name']} with {strategy.name}: {e}")
                                # Add error result
                                model_results.append({
                                    "model_full_name": model_name,
                                    "file_name": plan_data["file_name"],
                                    "original_code": plan_data["original_code"],
                                    "intended_vuln": plan_data["intended_vuln"],
                                    "rag_context": plan_data.get("rag_context", ""),
                                    "prompt_strategy": strategy.name, 
                                    "final_prompt": f"ERROR: {str(e)}",
                                    "generated_code": plan_data["original_code"],  # Return original on error
                                    "static_report": {},
                                    "static_confirmation_status": "ERROR",
                                    "static_interpreter_justification": f"Processing error: {str(e)}"
                                })
                            finally:
                                signal.alarm(0)
                            
                            # Update progress
                            progress.update(main_task, advance=1)
                    
                    logger.info(f"✅ {model_name}: Generated {len(model_results)} results")
                    return model_results
                    
                except Exception as e:
                    logger.error(f"❌ Critical error processing {model_name}: {e}")
                    # Advance progress for remaining tasks
                    remaining_tasks = len(plan_files) * len(strategies_to_run) - len(model_results)
                    progress.update(main_task, advance=remaining_tasks)
                    return model_results
            
            # Prepare models for sequential processing
            models_info = []
            for model_name in coders_to_run:
                model_info = CODER_MODELS[model_name]
                models_info.append({
                    'name': model_name,
                    'path': model_info['path']
                })
            
            # Check if ollama backend is requested
            use_ollama_phase2 = getattr(args, 'ollama', False)
            
            all_model_results = []
            if use_ollama_phase2:
                # Use Ollama directly — no need for sequential model manager
                console.print(f"[bold green]:rocket: Using Ollama backend for Phase 2[/bold green]")
                for model_info in models_info:
                    model_name = model_info['name']
                    logger.info(f"🚀 Processing {model_name} via Ollama")
                    ollama_llm = create_ollama_wrapper(model_name, stream_llm=_STREAM_LLM)
                    model_results = process_single_model(ollama_llm, model_name)
                    if model_results:
                        all_model_results.extend(model_results)
                        logger.info(f"✅ {model_name}: Added {len(model_results)} results")
                    else:
                        logger.error(f"❌ {model_name}: No results generated")
                        progress.update(main_task, advance=len(plan_files) * len(strategies_to_run))
            else:
                # Process models sequentially using the sequential manager (llama-cpp)
                sequential_manager = get_sequential_manager()
                sequential_manager.log_memory_status("before processing")
                
                for model_info in models_info:
                    model_name = model_info['name']
                    model_path = model_info['path']
                    
                    logger.info(f"🚀 Starting sequential processing of {model_name}")
                    
                    # Process this model with proper lifecycle management
                    model_results = sequential_manager.process_model_sequentially(
                        model_name, model_path, process_single_model
                    )
                    
                    if model_results:
                        all_model_results.extend(model_results)
                        logger.info(f"✅ {model_name}: Added {len(model_results)} results")
                    else:
                        logger.error(f"❌ {model_name}: No results generated")
                        # Advance progress for failed model
                        progress.update(main_task, advance=len(plan_files) * len(strategies_to_run))
                    
                    # Log memory status between models
                    sequential_manager.log_memory_status(f"after {model_name}")
            
            # Flatten results
            all_results = all_model_results
            logger.info(f"🎉 Sequential processing complete! Total results: {len(all_results)}")
            # ===================================================================
            
            console.print(f":floppy_disk: Saving {len(all_results)} generated snippets to [cyan]{gen_results_path}[/cyan]")
            with open(gen_results_path, "wb") as f:
                pickle.dump(all_results, f)
            console.print("✅ Generation complete and progress saved.")

    # --- PHASE 2b: STATIC ANALYSIS ---
    if args.stage in ['analyze', 'all']:
        console.print(Rule("[bold blue]:flashlight: Phase 2b: Running Static Analysis in Parallel (CPU Task)[/bold blue]"))
        if not os.path.exists(gen_results_path):
            console.print(f"[bold red]:x: Generated results not found. Please run the 'generate' stage first.[/bold red]")
            return
        with open(gen_results_path, "rb") as f: all_results = pickle.load(f)
        
        static_analysis_agent = StaticAnalysisAgent()
        def analyze_record(record):
            from trace_diagram import get_tracer
            _tr = get_tracer()
            try:
                # If validation passes, run the analysis
                record['static_report'] = static_analysis_agent.run_static_analysis(record['generated_code'])
                report = record['static_report']
                _tr.trace_analysis("Static analysis (Bandit + Semgrep + DeVAIC)",
                                   record.get('file_name', '?'),
                                   {
                                       'bandit_findings': report.get('bandit', {}),
                                       'semgrep_findings': report.get('semgrep', {}),
                                       'devaic_findings': report.get('devaic', {}),
                                       'strategy': record.get('prompt_strategy', '?'),
                                       'model': record.get('model_full_name', '?'),
                                   })
                # Status remains 'pending' for the next stage
            
            except Exception as e:
                # If validation fails, set a specific, machine-readable status
                error_message = f"Code validation failed: {e}"
                record['static_confirmation_status'] = "FAILURE (Syntax Error)"
                record['static_interpreter_justification'] = error_message
                record['semantic_confirmation_status'] = "FAILURE (Syntax Error)" # Also fail semantic
                record['semantic_justification'] = error_message
                record['static_report'] = {"error": error_message} # Add error to the report

            return record

        with ThreadPoolExecutor() as executor:
            with Progress(*progress_columns, console=console, transient=False) as progress:
                task = progress.add_task(f"[cyan] :beer: Analyzing {len(all_results)} snippets...", total=len(all_results))
                futures = [executor.submit(analyze_record, record) for record in all_results]
                for i, future in enumerate(futures):
                    all_results[i] = future.result()
                    progress.update(task, advance=1)
        del static_analysis_agent

        console.print(f"Saving {len(all_results)} analyzed snippets to [cyan]{analyzed_results_path}[/cyan]")
        with open(analyzed_results_path, "wb") as f:
            pickle.dump(all_results, f)
        console.print("✅ Analysis complete and progress saved.")

    # --- PHASE 2c/d: EVALUATION & LOGGING ---
    if args.stage in ['evaluate', 'all']:
        run_evaluation_stage(args, results_pickle_path=analyzed_results_path)

                
def run_reanalysis_phase(args_or_config):
    """
    Phase 'reanalyze': A robust, two-stage process.
    1. Runs static analysis on all jobs (if not already done).
    2. Runs the memory-efficient batch evaluation and logging.
    
    Args:
        args_or_config: Either argparse.Namespace (legacy) or dict (config-driven)
    """
    console.print(Rule("[bold yellow]VAITP: Re-Analysis Phase[/bold yellow]"))
    
    # Handle both config dict and args namespace for backward compatibility
    if isinstance(args_or_config, dict):
        config = args_or_config
        input_pickle = config.get('input_pickle')
        expected_dir = config.get('expected_dir')
        # Create args-like object for backward compatibility with existing functions
        args = argparse.Namespace()
        args.input_pickle = input_pickle
        args.expected_dir = expected_dir
    else:
        args = args_or_config
        input_pickle = args.input_pickle
    
    # --- Define file paths ---
    job_queue_file = os.path.join(PROMPTS_DIR, "reanalysis_jobs.json")
    if input_pickle:
        analyzed_results_path = input_pickle
        console.print(f"[yellow]Using specified input file: {analyzed_results_path}[/yellow]")
    else:
        analyzed_results_path = os.path.join(PROMPTS_DIR, "reanalyzed_results.pkl")

    # =================================================================
    #  STAGE 1: STATIC ANALYSIS (Only if necessary)
    # =================================================================
    if not os.path.exists(analyzed_results_path):
        console.print(Rule("[bold blue]Step 1: Running Static Analysis[/bold blue]"))
        if not os.path.exists(job_queue_file):
            console.print(f"[bold red]Error: Job queue not found at {job_queue_file}. Please run prepare_reanalysis.py first.[/bold red]")
            return
            
        with open(job_queue_file, 'r') as f:
            all_jobs = json.load(f)

        console.print(f"Found {len(all_jobs)} snippets to analyze.")
        
        # Convert jobs to the format expected by the analysis stage
        all_results = []
        for job in all_jobs:
            all_results.append({
                "model_full_name": job['model_name'],
                "file_name": job['target_filename'],
                "intended_vuln": {"type": job['vulnerability_type'], "expected_pattern": ""},
                "rag_context": job.get("rag_context", ""),
                "prompt_strategy": job['prompt_strategy'],
                "final_prompt": job['final_prompt'],
                "generated_code": job['generated_code'],
                "static_report": {},
                "static_confirmation_status": "pending",
                "static_interpreter_justification": "pending"
            })

        static_analysis_agent = StaticAnalysisAgent()
        progress_columns = (SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn())
        
        def analyze_record(record):
            try:
                # TODO: change this to validate if argv is there
                #validate_python_script(record['generated_code'])
                record['static_report'] = static_analysis_agent.run_static_analysis(record['generated_code'])
            except Exception as e:
                record['static_confirmation_status'] = "FAILURE (Syntax Error)"
                record['static_interpreter_justification'] = f"Code validation failed: {e}"
            return record

        with ThreadPoolExecutor() as executor:
            with Progress(*progress_columns, console=console, transient=False) as progress:
                task = progress.add_task(f"[cyan] :mag: Analyzing {len(all_results)} snippets...", total=len(all_results))
                futures = [executor.submit(analyze_record, record) for record in all_results]
                for i, future in enumerate(futures):
                    all_results[i] = future.result()
                    progress.update(task, advance=1)
        
        with open(analyzed_results_path, "wb") as f:
            pickle.dump(all_results, f)
        console.print(f"✅ Analysis complete. Progress saved to [cyan]{analyzed_results_path}[/cyan]")
    else:
        console.print(f"✅ Found existing analysis file at [cyan]{analyzed_results_path}[/cyan]. Skipping analysis stage.")

    # =================================================================
    #  STAGE 2: EVALUATION AND LOGGING (Always runs)
    # =================================================================
    # This calls the separate, robust evaluation function we designed
    run_evaluation_stage(args, results_pickle_path=analyzed_results_path)

def save_dataframes_to_files(df: pd.DataFrame, args: argparse.Namespace):
    """
    Handles saving the results DataFrame to CSV and single/multiple Excel files.
    """
    console.print(Rule("[bold blue]:bar_chart: Saving Final Results[/bold blue]"))
    db_dir = os.path.dirname(DB_PATH)

    # --- Step 1: Always save the full CSV as a robust backup ---
    try:
        csv_path = os.path.join(db_dir, "vaitp_results.csv")
        df.to_csv(
            csv_path,
            index=False,
            quoting=csv.QUOTE_ALL, # Force quotes around every field
            escapechar='\\'      # Use a backslash to escape quotes inside a field
        )
        console.print(f"✅ [bold green]Full results saved to CSV:[/bold green] [cyan]{csv_path}[/cyan]")
    except Exception as e:
        console.print(f"[bold yellow]⚠️  Warning: Failed to save full CSV file.[/bold yellow]")
        console.print(f"[dim]Error details: {e}[/dim]")

    # Define which columns might be too long (used by both Excel export options)
    long_text_columns = [
        'rag_context', 'final_prompt', 'original_code',
        'expected_code', 'generated_code', 'static_analysis_report',
        'static_interpreter_justification', 'semantic_justification'
    ]

    # --- Step 2: Save the single, combined Excel file if requested ---
    if args.save_excel:
        try:
            console.print("Attempting to save combined Excel file...")
            # =======================================================================
            # === Truncate long columns before saving to Excel ===
            # =======================================================================
            # Create a copy to avoid modifying the original DataFrame
            excel_df = df.copy()
            
            # Truncate each of these columns to a safe length (e.g., 30,000 chars)
            for col in long_text_columns:
                if col in excel_df.columns:
                    excel_df[col] = excel_df[col].astype(str).apply(sanitize_for_excel)
            
            # The strip_ansi_codes step should now be on the new df
            sanitized_df = excel_df.map(lambda x: strip_ansi_codes(str(x)))
            # =======================================================================

            excel_path = os.path.join(db_dir, "vaitp_results.xlsx")
            sanitized_df.to_excel(excel_path, index=False)
            console.print(f"✅ [bold green]Full results saved to Excel:[/bold green] [cyan]{excel_path}[/cyan]")
        except Exception as e:
            console.print(f"[bold yellow]⚠️  Warning: Failed to save combined Excel file.[/bold yellow]")
            console.print(f"[dim]Error details: {e}[/dim]")

    # =============================================================================
    # === Save a separate Excel file for each model if requested (for Roberta) ====
    # =============================================================================
    if args.excel_per_model:
        console.print(Rule("[bold blue]:page_facing_up: Saving Per-Model Excel Files[/bold blue]"))
        unique_models = df['model_name'].unique()
        console.print(f"Found {len(unique_models)} unique models to export.")

        for model_name in unique_models:
            try:
                console.print(f"Exporting results for [cyan]{model_name}[/cyan]...")
                model_df = df[df['model_name'] == model_name]
                
                # Sanitize the model name to create a valid filename
                safe_model_name = model_name.replace('/', '_').replace(' ', '_').replace(':', '')
                model_excel_path = os.path.join(db_dir, f"vaitp_results_{safe_model_name}.xlsx")

                excel_model_df = model_df.copy()
                for col in long_text_columns:
                    if col in excel_model_df.columns:
                        excel_model_df[col] = excel_model_df[col].astype(str).apply(sanitize_for_excel)
                
                sanitized_model_df = excel_model_df.map(lambda x: strip_ansi_codes(str(x)))
                sanitized_model_df.to_excel(model_excel_path, index=False)
                
                console.print(f"  -> ✅ [bold green]Saved to:[/bold green] [cyan]{model_excel_path}[/cyan]")
            except Exception as e:
                console.print(f"  -> ❌ [bold red]Failed to save Excel file for {model_name}.[/bold red]")
                console.print(f"     [dim]Error details: {e}[/dim]") 
        
def run_evaluation_stage(args, results_pickle_path: str):
    """
    Runs the memory-intensive evaluation stage in batches with enhanced quantitative metrics.
    This function is truly resumable by checking the database for completed jobs.
    Enhanced to include BLEU scoring for quantitative code similarity evaluation.
    """
    logger = setup_logging()
    console.print(Rule("[bold yellow]:lady_beetle: Running Evaluation Stage in Batches (Resumable)[/bold yellow]"))

    if not os.path.exists(results_pickle_path):
        console.print(f"[bold red]:x: Analyzed results not found at {results_pickle_path}. Aborting.[/bold red]")
        return
        
    with open(results_pickle_path, "rb") as f:
        all_possible_jobs = pickle.load(f)

    console.print("Checking database for previously completed jobs to resume...")
    completed_jobs = set()
    try:
        from config import DB_PATH
        if os.path.exists(DB_PATH):
            con = sqlite3.connect(DB_PATH)
            completed_df = pd.read_sql_query("SELECT DISTINCT model_name, target_filename, prompt_strategy FROM comparative_analysis_runs", con)
            # ---------------------------
            con.close()
            completed_jobs = set(tuple(row) for row in completed_df.itertuples(index=False))
            console.print(f"Found {len(completed_jobs)} completed jobs in the database.")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read existing database to check for completed jobs: {e}[/yellow]")

    pending_evaluation = []
    for record in all_possible_jobs:
        # Use the correct key names from the pickle record to build the key
        job_key = (record['model_full_name'], record['file_name'], record['prompt_strategy'])
        if job_key not in completed_jobs:
            pending_evaluation.append(record)

    if not pending_evaluation:
        console.print("✅ All records have already been evaluated and logged. Nothing to do.")
    else:
        console.print(f"[bold green]Identified {len(pending_evaluation)} records remaining to be evaluated.[/bold green]")

        console.print(f":spouting_whale: Loading Confirmation LLM: [bold cyan]{args.model}[/bold cyan]")
        confirmation_llm = initialize_llm(REASONING_MODELS[args.model]['path'])
        if not confirmation_llm: return
        # Wrap for tracing
        from trace_diagram import wrap_llm_for_tracing
        confirmation_llm = wrap_llm_for_tracing(confirmation_llm, args.model, "Phase 2 - Static/semantic evaluation")

        # Optional jury for the semantic-correctness judgement (categorical
        # SUCCESS/FAILURE). Allowlist-gated: only fires when 'phase2.semantic_confirm'
        # is listed in the voting config. CAVEAT: this evaluation runs in parallel
        # workers, so each vote fans out N jurors + judge concurrently — enable it
        # only with serial evaluation (or expect heavy local GPU contention).
        _cfa_voting = getattr(args, 'voting_config', None)
        if _cfa_voting:
            try:
                from orchestration.voting_jury import load_voting_config as _lvc, build_jury as _bj
                _cfg2 = _lvc(_cfa_voting)
                _jury2 = _bj(_cfg2, tracer=None)
                if _jury2 is not None and 'phase2.semantic_confirm' in _cfg2.decisions:
                    console.print("[bold green]:ballot_box: Jury enabled for phase2.semantic_confirm[/bold green]")
                    confirmation_llm = _jury2.make_llama_wrapper('phase2.semantic_confirm')
            except Exception as _e2:
                console.print(f"[bold yellow]  Voting config load failed for confirmation ({_e2}).[/bold yellow]")

        confirmation_agent = DynamicConfirmationAgent_StaticInterpreter(confirmation_llm)
        
        # Initialize code similarity evaluator for quantitative metrics
        from code_similarity_evaluator import CodeSimilarityEvaluator
        similarity_evaluator = CodeSimilarityEvaluator()
        
        # Determine optimal number of parallel workers based on system resources
        from adaptive_resource_manager import get_resource_manager
        resource_manager = get_resource_manager()
        profile = resource_manager.refresh_resources()
        
        # Calculate optimal workers based on available resources
        # Use conservative approach: 1 worker per 2GB of available memory, max 8 workers
        max_workers = min(8, max(1, int(profile.available_memory_gb // 2)))
        
        # Reduce workers if CPU usage is high
        if profile.cpu_percent > 80:
            max_workers = max(1, max_workers // 2)
        
        console.print(f"[bold green]🚀 Using {max_workers} parallel workers for evaluation (Available: {profile.available_memory_gb:.1f}GB RAM, CPU: {profile.cpu_percent:.1f}%)[/bold green]")
        
        progress_columns = (SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn())

        # Use parallel execution for evaluation
        if max_workers > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import threading
            
            # Thread-safe progress tracking
            progress_lock = threading.Lock()
            
            def evaluate_single_record(record_data):
                """Evaluate a single record in parallel."""
                i, record = record_data
                try:
                    # Create thread-local instances to avoid conflicts
                    from orchestration.injection_agents import DynamicConfirmationAgent_StaticInterpreter
                    thread_confirmation_agent = DynamicConfirmationAgent_StaticInterpreter(confirmation_llm)
                    
                    from code_similarity_evaluator import CodeSimilarityEvaluator
                    thread_similarity_evaluator = CodeSimilarityEvaluator()
                    
                    # Perform evaluation (same logic as sequential)
                    if record.get('static_confirmation_status') == "FAILURE (Syntax Error)":
                        logger.warning(f"Record {i} has pre-existing syntax error. Continuing evaluation...")
                    
                    # 1. Mechanical Check
                    static_confirmed, static_justification = thread_confirmation_agent.evaluate_static_analysis(
                        static_analysis_report=record['static_report']
                    )
                    
                    from trace_diagram import get_tracer as _get_tracer_eval
                    _tr_eval = _get_tracer_eval()
                    _tr_eval.trace_analysis("LLM evaluation of static analysis",
                                           record.get('file_name', '?'),
                                           {'verdict': 'CONFIRMED' if static_confirmed else 'NOT CONFIRMED',
                                            'justification': static_justification,
                                            'strategy': record.get('prompt_strategy', '?')})

                    # 2. Semantic Check
                    cleaned_generated_code = clean_code(record['generated_code'])
                    semantic_confirmed, semantic_justification = thread_confirmation_agent.evaluate_semantic_correctness(
                        original_code=record['original_code'],
                        modified_code_no_comments=cleaned_generated_code,
                        intended_vuln_details=record['intended_vuln'],
                        task_prompt_given_to_coder=record["final_prompt"]
                    )
                    _tr_eval.trace_analysis("LLM semantic correctness evaluation",
                                           record.get('file_name', '?'),
                                           {'verdict': 'CONFIRMED' if semantic_confirmed else 'NOT CONFIRMED',
                                            'justification': semantic_justification,
                                            'strategy': record.get('prompt_strategy', '?')})
                    
                    # 3. Quantitative Evaluation - Calculate BLEU score
                    bleu_score = None
                    expected_code = ""
                    metrics = None
                    
                    if args.expected_dir:
                        expected_file_path = os.path.join(args.expected_dir, record['file_name'])
                        content = load_file_content(expected_file_path)
                        if content:
                            expected_code = content
                            try:
                                metrics = thread_similarity_evaluator.evaluate_all_metrics(
                                    record['generated_code'], expected_code
                                )
                                bleu_score = metrics.bleu_4_score if metrics else None
                            except Exception as e:
                                logger.warning(f"Failed to calculate metrics for {record['file_name']}: {e}")
                                try:
                                    bleu_score = thread_similarity_evaluator.calculate_bleu_score(
                                        record['generated_code'], expected_code
                                    )
                                    logger.warning("Using legacy BLEU calculation as fallback")
                                    metrics = None
                                except Exception as fallback_error:
                                    logger.error(f"Legacy BLEU fallback also failed: {fallback_error}")
                                    bleu_score = None
                                    metrics = None
                        else:
                            logger.warning(f"Expected code file not found for {record['file_name']} in {args.expected_dir}")
                    
                    return {
                        'index': i,
                        'record': record,
                        'static_confirmed': static_confirmed,
                        'static_justification': static_justification,
                        'semantic_confirmed': semantic_confirmed,
                        'semantic_justification': semantic_justification,
                        'bleu_score': bleu_score,
                        'expected_code': expected_code,
                        'metrics': metrics,
                        'error': None
                    }
                    
                except Exception as e:
                    logger.error(f"Error evaluating record {i}: {e}")
                    return {
                        'index': i,
                        'record': record,
                        'error': str(e)
                    }
            
            with Progress(*progress_columns, console=console, transient=False) as progress:
                task = progress.add_task(f"[cyan]:books: Evaluating {len(pending_evaluation)} reports...", total=len(pending_evaluation))
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all evaluation tasks
                    future_to_record = {
                        executor.submit(evaluate_single_record, (i, record)): i 
                        for i, record in enumerate(pending_evaluation)
                    }
                    
                    # Process completed evaluations
                    for future in as_completed(future_to_record):
                        result = future.result()
                        
                        if result['error']:
                            logger.error(f"Failed to evaluate record {result['index']}: {result['error']}")
                            with progress_lock:
                                progress.update(task, advance=1)
                            continue
                        
                        # Log the result (same logic as sequential)
                        record = result['record']
                        static_confirmed = result['static_confirmed']
                        static_justification = result['static_justification']
                        semantic_confirmed = result['semantic_confirmed']
                        semantic_justification = result['semantic_justification']
                        bleu_score = result['bleu_score']
                        expected_code = result['expected_code']
                        metrics = result['metrics']
                        
                        static_status_str = "SUCCESS" if static_confirmed else "FAILURE"
                        semantic_status_str = "SUCCESS" if semantic_confirmed else "FAILURE"
                        model_type_str = "finetuned" if "finetuned" in record['model_full_name'].lower() else "base"
                        logged_rag_context = "" if record['prompt_strategy'].endswith("_ONLY") else record['rag_context']

                        failure_reason = "NONE"
                        if not record['generated_code'].strip():
                            failure_reason = "REFUSAL"
                        elif record['static_confirmation_status'] == "FAILURE (Syntax Error)":
                            failure_reason = "SYNTAX_ERROR"
                        elif static_status_str == "SUCCESS" and semantic_status_str == "FAILURE":
                            failure_reason = "SEMANTIC_FAILURE"
                        elif static_status_str == "FAILURE" and semantic_status_str == "FAILURE":
                            failure_reason = "LOGICAL_FAILURE"
                        elif static_status_str == "FAILURE" and semantic_status_str == "SUCCESS":
                            failure_reason = "TOOL_MISMATCH"
                        
                        log_comparative_run(
                            model_full_name=record['model_full_name'],
                            file_name=record['file_name'],
                            vulnerability_type=record['intended_vuln'].get("type", "N/A"),
                            model_type=model_type_str,
                            prompt_strategy=record['prompt_strategy'],
                            rag_context=logged_rag_context,
                            final_prompt=record['final_prompt'],
                            original_code=record['original_code'],
                            expected_code=expected_code, 
                            generated_code=record['generated_code'],
                            static_confirmation_status=static_status_str,
                            static_analysis_report=record['static_report'],
                            static_interpreter_justification=static_justification,
                            semantic_confirmation_status=semantic_status_str,
                            semantic_justification=semantic_justification,
                            failure_reason=failure_reason,
                            final_metrics=metrics
                        )
                        
                        with progress_lock:
                            progress.update(task, advance=1)
        else:
            # Fallback to sequential processing
            with Progress(*progress_columns, console=console, transient=False) as progress:
                task = progress.add_task(f"[cyan]:books: Evaluating {len(pending_evaluation)} reports...", total=len(pending_evaluation))
                
                for i, record in enumerate(pending_evaluation):
                    # ===================================================================
                    # === Enhanced evaluation with quantitative metrics ===
                    # ===================================================================

                    #print(f"\n[DEBUG] --- Starting record {i} ({record['file_name']} | {record['model_full_name']} | {record['prompt_strategy']}) ---")

                    
                    if record.get('static_confirmation_status') == "FAILURE (Syntax Error)":
                        print(f"[WARNING] Record {i} has pre-existing syntax error. NOT skipping evaluation! Good luck sailor!")
                        #progress.update(task, advance=1)
                        #print(f"[DEBUG] --- Finished record {i} ---")
                        #continue

                    # 1. Mechanical Check
                    #print(f"[DEBUG] Record {i}: Calling evaluate_static_analysis...")
                    static_confirmed, static_justification = confirmation_agent.evaluate_static_analysis(
                        static_analysis_report=record['static_report']
                    )
                    
                    from trace_diagram import get_tracer as _get_tracer_eval2
                    _tr_eval2 = _get_tracer_eval2()
                    _tr_eval2.trace_analysis("LLM evaluation of static analysis",
                                            record.get('file_name', '?'),
                                            {'verdict': 'CONFIRMED' if static_confirmed else 'NOT CONFIRMED',
                                             'justification': static_justification,
                                             'strategy': record.get('prompt_strategy', '?')})

                    # 2. Semantic Check
                    cleaned_generated_code = clean_code(record['generated_code'])
                    semantic_confirmed, semantic_justification = confirmation_agent.evaluate_semantic_correctness(
                        original_code=record['original_code'],
                        modified_code_no_comments=cleaned_generated_code,
                        intended_vuln_details=record['intended_vuln'],
                        task_prompt_given_to_coder=record["final_prompt"]
                    )
                    _tr_eval2.trace_analysis("LLM semantic correctness evaluation",
                                            record.get('file_name', '?'),
                                            {'verdict': 'CONFIRMED' if semantic_confirmed else 'NOT CONFIRMED',
                                             'justification': semantic_justification,
                                             'strategy': record.get('prompt_strategy', '?')})

                    # 3. Quantitative Evaluation - Calculate BLEU score
                    bleu_score = None
                    expected_code = ""
                    metrics = None
                    if args.expected_dir:
                        expected_file_path = os.path.join(args.expected_dir, record['file_name'])
                        # Use our robust load_file_content utility
                        content = load_file_content(expected_file_path)
                        if content:
                            expected_code = content
                            try:
                                # Use new comprehensive metrics API
                                metrics = similarity_evaluator.evaluate_all_metrics(
                                    record['generated_code'], expected_code
                                )
                                # Maintain backward compatibility with legacy BLEU score
                                bleu_score = metrics.bleu_4_score if metrics else None
                                #print(f"[DEBUG] Record {i}: Calculated metrics: BLEU-4={bleu_score}")
                            except Exception as e:
                                logger.warning(f"Failed to calculate metrics for {record['file_name']}: {e}")
                                # Fallback to legacy method if new API fails
                                try:
                                    bleu_score = similarity_evaluator.calculate_bleu_score(
                                        record['generated_code'], expected_code
                                    )
                                    logger.warning("Using legacy BLEU calculation as fallback")
                                    metrics = None
                                except Exception as fallback_error:
                                    logger.error(f"Legacy BLEU fallback also failed: {fallback_error}")
                                    bleu_score = None
                                    metrics = None
                        else:
                            logger.warning(f"Expected code file not found for {record['file_name']} in {args.expected_dir}")

                    # 4. Logging with enhanced metrics
                    #print(f"[DEBUG] Record {i}: Preparing to log to database...")
                    static_status_str = "SUCCESS" if static_confirmed else "FAILURE"
                    semantic_status_str = "SUCCESS" if semantic_confirmed else "FAILURE"
                    model_type_str = "finetuned" if "finetuned" in record['model_full_name'].lower() else "base"
                    logged_rag_context = "" if record['prompt_strategy'].endswith("_ONLY") else record['rag_context']

                    failure_reason = "NONE"
                    if not record['generated_code'].strip():
                        failure_reason = "REFUSAL"
                    elif record['static_confirmation_status'] == "FAILURE (Syntax Error)":
                        failure_reason = "SYNTAX_ERROR"
                    elif static_status_str == "SUCCESS" and semantic_status_str == "FAILURE":
                        failure_reason = "SEMANTIC_FAILURE" # Tool saw a flaw, but LLM says it's not the right one.
                    elif static_status_str == "FAILURE" and semantic_status_str == "FAILURE":
                        failure_reason = "LOGICAL_FAILURE" # No flaw found and LLM agrees it failed.
                    elif static_status_str == "FAILURE" and semantic_status_str == "SUCCESS":
                        failure_reason = "TOOL_MISMATCH" # Tool found nothing, but LLM says it's correct.
                    
                    log_comparative_run(
                        model_full_name=record['model_full_name'],
                        file_name=record['file_name'],
                        vulnerability_type=record['intended_vuln'].get("type", "N/A"),
                        model_type=model_type_str,
                        prompt_strategy=record['prompt_strategy'],
                        rag_context=logged_rag_context,
                        final_prompt=record['final_prompt'],
                        original_code=record['original_code'],
                        expected_code=expected_code, 
                        generated_code=record['generated_code'],
                        static_confirmation_status=static_status_str,
                        static_analysis_report=record['static_report'],
                        static_interpreter_justification=static_justification,
                        semantic_confirmation_status=semantic_status_str,
                        semantic_justification=semantic_justification,
                        failure_reason=failure_reason,
                        final_metrics=metrics  # Pass comprehensive metrics
                    )
                
                    progress.update(task, advance=1)
        
        del confirmation_llm, confirmation_agent, similarity_evaluator
        clear_memory()

    # The new logic checks if ANY export is needed before querying the DB again.
    if args.save_excel or args.excel_per_model:
        try:
            con = sqlite3.connect(DB_PATH)
            final_df = pd.read_sql_query("SELECT * from comparative_analysis_runs", con)
            con.close()
            save_dataframes_to_files(final_df, args)
        except Exception as e:
            console.print(f"[bold red]❌ Error during final data export: {e}[/bold red]")

def _validate_vulnerability(vuln_code: str, patch_code: str, intended_vuln: dict) -> tuple:
    """
    Validate that generated vulnerable code actually contains the intended vulnerability.
    Returns (is_valid, diagnosis) where diagnosis explains what's wrong if invalid.
    
    Uses static pattern matching to check that the vulnerability was properly injected.
    This catches the common Phase 2 failure mode where the LLM generates code that
    looks different but is NOT actually vulnerable (e.g., still uses json.loads instead
    of pickle.loads, or uses subprocess with list args instead of shell=True).
    """
    vuln_type = intended_vuln.get("type", "").lower()
    vuln_lower = vuln_code.lower()
    patch_lower = patch_code.lower()

    # --- Helper: normalize code by stripping comments and trailing whitespace ---
    def _normalize(code):
        lines = [re.sub(r'#.*$', '', line).rstrip() for line in code.splitlines()]
        return '\n'.join(line for line in lines if line.strip())

    # --- YAML (check before pickle since both can be CWE-502) ---
    if "yaml" in vuln_type:
        if "yaml" in vuln_lower:
            if "yaml.safe_load" in vuln_lower:
                return False, "Code uses yaml.safe_load() which is safe. Must use yaml.load() with yaml.Loader or yaml.UnsafeLoader."
            if "fullloader" in vuln_lower and "unsafeloader" not in vuln_lower and "yaml.loader" not in vuln_lower:
                return False, "Code uses yaml.FullLoader which blocks !!python/object/apply. Must use yaml.Loader or yaml.UnsafeLoader."

    # --- NoSQL Injection (MUST be checked BEFORE SQL injection since "NoSQL Injection" contains "sql injection") ---
    elif "nosql" in vuln_type or "cwe-943" in vuln_type:
        # NoSQL injection requires that user input (password) can be a dict like {"$ne": ""}
        # If the vuln code has isinstance() type checking, dict operators are blocked
        vuln_has_isinstance = bool(re.search(r'isinstance\s*\(\s*\w+\s*,\s*str\s*\)', vuln_code))
        patch_has_isinstance = bool(re.search(r'isinstance\s*\(\s*\w+\s*,\s*str\s*\)', patch_code))
        if vuln_has_isinstance and patch_has_isinstance:
            # Both have type checking — vuln didn't remove it, NOT exploitable
            return False, "Code has isinstance(x, str) type checking which blocks NoSQL operator injection ({\"$ne\": \"\"}). Must remove type validation."
        # Also check if vuln uses pickle.loads instead of get_json — wrong vuln type
        if "pickle.loads" in vuln_lower and "get_json" not in vuln_lower:
            return False, "Code uses pickle.loads(request.data) instead of request.get_json(). This changes the vulnerability type from NoSQL injection to pickle deserialization."

    # --- SQL Injection ---
    elif "sql injection" in vuln_type or "cwe-89" in vuln_type:
        # Vuln must use string formatting in SQL, not parameterized queries.
        # Parameterized query styles:
        #   - sqlite3/DB-API: cursor.execute("... ? ...", (val,))
        #   - MySQLdb/pymysql: cursor.execute("... %s ...", (val,))
        # The key indicator is execute() with a TUPLE as the second argument.
        has_param_qmark = "?" in vuln_code and "execute(" in vuln_lower
        # MySQLdb uses %s as parameter placeholders WITH a tuple arg — detect this
        # by looking for execute("...%s...", (var, ...)) pattern
        has_param_percent = bool(re.search(
            r'execute\s*\(\s*["\'].*%s.*["\']\s*,\s*\(',
            vuln_code
        ))
        has_param = has_param_qmark or has_param_percent
        has_fstring = ("f\"" in vuln_code or "f'" in vuln_code) and "execute" in vuln_lower
        has_concat = ("+ " in vuln_code or ".format(" in vuln_code) and "execute" in vuln_lower
        if has_param and not has_fstring and not has_concat:
            return False, "SQL query still uses parameterized queries (%s with tuple args or ?). Must use string formatting/concatenation (f-string, .format(), or + concatenation)."
        if not has_fstring and not has_concat and "execute" in vuln_lower:
            # Check for string concat patterns more broadly
            if "'" + "'" not in vuln_code and "format(" not in vuln_code:
                # Only flag if there's no evidence of string interpolation in the execute call
                exec_match = re.search(r'execute\s*\((.+?)\)', vuln_code, re.DOTALL)
                if exec_match:
                    exec_arg = exec_match.group(1)
                    if "f'" not in exec_arg and 'f"' not in exec_arg and "+" not in exec_arg and ".format(" not in exec_arg:
                        return False, "SQL query does not use string formatting. Must inject user input directly into query string."

    # --- Command Injection ---
    elif "command injection" in vuln_type or "cwe-78" in vuln_type:
        if "subprocess" in vuln_lower:
            # Must have shell=True with string arg, or os.system/os.popen
            has_shell_true = "shell=true" in vuln_lower
            has_list_args = re.search(r'subprocess\.\w+\(\s*\[', vuln_code)
            has_os_system = "os.system(" in vuln_lower or "os.popen(" in vuln_lower
            if has_list_args and not has_shell_true and not has_os_system:
                return False, "subprocess uses list args without shell=True. Must use shell=True with string arg or os.system()."
            # List args WITH shell=True is also NOT vulnerable — user input is passed as $1/$2 positional params, not in the command string
            if has_list_args and has_shell_true and not has_os_system:
                return False, "subprocess uses list args with shell=True. User input is passed as positional params ($1, $2), not in the command string. Must use a string arg with shell=True (e.g., subprocess.run(f'cmd {user_input}', shell=True))."
            # String arg without shell=True is also NOT vulnerable — subprocess tries to exec the whole string as a program name
            if not has_list_args and not has_shell_true and not has_os_system:
                return False, "subprocess uses string arg without shell=True. Must add shell=True for command injection to work, or use os.system()."
            if "shlex.quote" in vuln_lower:
                return False, "Code uses shlex.quote() which sanitizes input. Must remove input sanitization."

    # --- Pickle Deserialization (not YAML) ---
    elif ("pickle" in vuln_type or "deserialization" in vuln_type or "cwe-502" in vuln_type) and "yaml" not in vuln_type:
        has_pickle_loads = "pickle.loads" in vuln_lower or "pickle.load(" in vuln_lower
        # Also match Unpickler(...).load() patterns (e.g. RestrictedUnpickler)
        has_unpickler = bool(re.search(r'[Uu]npickler\s*\(', vuln_code))
        if not has_pickle_loads and not has_unpickler:
            if "json.loads" in vuln_lower:
                return False, "Code uses json.loads() instead of pickle.loads(). Must use pickle.loads() for deserialization vulnerability."
            return False, "Code does not call pickle.loads() or pickle.load(). Must use unsafe pickle deserialization."

    # --- SSTI / Template Injection (Jinja2, Mako, etc.) ---
    elif "ssti" in vuln_type or "template injection" in vuln_type or "cwe-1336" in vuln_type or "cwe-94" in vuln_type:
        # User input must be IN the template string, not passed as a variable.
        # Safe: Template("Hello {{ name }}").render(name=user_input)  — user input is DATA
        # Vulnerable: Template(f"Hello {user_input}").render()  — user input is TEMPLATE
        # Also vulnerable: render_template_string(user_input)
        # Mako safe: Template("Hello ${name}").render(name=user_input)
        # Mako vulnerable: Template(user_input).render()
        is_mako = "mako" in vuln_type or "mako" in vuln_lower
        has_jinja_var = "{{ " in vuln_code and "}}" in vuln_code
        has_mako_var = "${" in vuln_code and "}" in vuln_code and is_mako
        has_template_var = has_jinja_var or has_mako_var
        has_render_string = "render_template_string" in vuln_code
        # Check if Template() is called with a STATIC string containing {{ }} or ${}
        has_static_template = bool(re.search(r'Template\s*\(\s*["\'].*(\{\{.*\}\}|\$\{.*\}).*["\']\s*\)', vuln_code))
        # Also detect indirect static templates: template_str = "...{{ }}..." then Template(template_str)
        has_indirect_static = False
        template_var_match = re.search(r'(\w+)\s*=\s*["\'].*(\{\{.*\}\}|\$\{.*\}).*["\']', vuln_code)
        if template_var_match:
            var_name = template_var_match.group(1)
            if re.search(r'Template\s*\(\s*' + re.escape(var_name) + r'\s*\)', vuln_code):
                has_indirect_static = True
        # Check for render_template_string with a static template variable
        has_render_string_static = False
        if has_render_string:
            rts_match = re.search(r'render_template_string\s*\(\s*(\w+)', vuln_code)
            if rts_match:
                rts_var = rts_match.group(1)
                # Check if this variable is a static string with {{ }}
                if re.search(re.escape(rts_var) + r'\s*=\s*["\'].*\{\{.*\}\}.*["\']', vuln_code):
                    has_render_string_static = True
        # Check for user input directly in Template() — must be f-string/concat INSIDE the Template() call
        # NOT just any f-string anywhere in the code (e.g. f"Error: {e}" is irrelevant)
        has_user_in_template = False
        template_call_match = re.search(r'Template\s*\((.*?)\)', vuln_code, re.DOTALL)
        if template_call_match:
            template_arg = template_call_match.group(1)
            if any(x in template_arg for x in ['f"', "f'", '+', '.format(']):
                has_user_in_template = True
        # Also check: Template(user_variable) where user_variable comes from input
        has_template_with_var = bool(re.search(r'Template\s*\(\s*\w+\s*\)', vuln_code)) and not has_static_template and not has_indirect_static
        if (has_static_template or has_indirect_static) and not has_user_in_template and not (has_render_string and not has_render_string_static):
            return False, "Template uses variable substitution (safe). Must embed user input directly in template string via Template(user_input) or render_template_string(user_input)."
        if has_render_string_static and not has_user_in_template:
            return False, "render_template_string uses a static template with {{ variable }} (safe). Must pass user input directly as the template string."
        if has_template_var and not has_user_in_template and not has_render_string and not has_template_with_var:
            # Broader check: if there's {{ }} or ${} but no evidence of user input in template
            return False, "Template uses variable substitution (safe). Must embed user input directly in template string via Template(user_input) or render_template_string(user_input)."

    # --- JWT ---
    elif "jwt" in vuln_type or "cwe-345" in vuln_type:
        if "jwt.decode" in vuln_lower:
            # JWT algorithm confusion requires that the decode call does NOT restrict algorithms
            # or allows 'none'. If algorithms=["HS256"] is specified, it's safe.
            has_algorithms_param = bool(re.search(r'jwt\.decode\s*\([^)]*algorithms\s*=', vuln_code))
            if has_algorithms_param:
                # Check if it only allows HS256 (safe)
                allows_none = 'none' in vuln_lower and 'algorithms' in vuln_lower
                if not allows_none:
                    # Check if vuln and patch are functionally the same JWT decode
                    patch_has_algorithms = bool(re.search(r'jwt\.decode\s*\([^)]*algorithms\s*=', patch_code))
                    if patch_has_algorithms:
                        # Both specify algorithms — check if the vuln actually removed the restriction
                        vuln_algos = re.search(r'algorithms\s*=\s*\[([^\]]*)\]', vuln_code)
                        patch_algos = re.search(r'algorithms\s*=\s*\[([^\]]*)\]', patch_code)
                        if vuln_algos and patch_algos and vuln_algos.group(1).strip() == patch_algos.group(1).strip():
                            return False, "JWT decode uses same algorithms restriction as patched code. Must remove algorithms parameter or allow 'none' algorithm."

    # --- SSRF ---
    elif "ssrf" in vuln_type or "cwe-918" in vuln_type:
        # Check that the vuln actually removed the IP/hostname validation
        if vuln_code.strip() == patch_code.strip():
            return False, "Vulnerable code is identical to patched code."
        if _normalize(vuln_code) == _normalize(patch_code):
            return False, "Vulnerable code is functionally identical to patched code (only comments differ)."

    # --- Header Injection ---
    elif "header" in vuln_type and "injection" in vuln_type:
        # First check if vuln and patch are functionally identical (only differ in comments)
        if _normalize(vuln_code) == _normalize(patch_code):
            return False, "Vulnerable code is functionally identical to patched code (only comments differ). Must introduce actual vulnerability (e.g., pass header value to os.system/subprocess)."
        has_os_system = "os.system(" in vuln_lower or "os.popen(" in vuln_lower or "subprocess" in vuln_lower
        if not has_os_system:
            return False, "Code does not pass header values to os.system/subprocess. Must use header value in shell command."

    # --- GitPython (CVE-2022-24439) ---
    elif "gitpython" in vuln_type or "cve-2022-24439" in vuln_type:
        if "urlparse" in vuln_lower and "scheme" in vuln_lower:
            # Check if scheme validation blocks ext::
            if re.search(r'scheme\s+not\s+in.*\[.*https.*\]', vuln_lower):
                return False, "Code validates URL scheme which blocks ext:: protocol. Must remove scheme validation."

    # --- Open Redirect (CWE-601) ---
    elif "open redirect" in vuln_type or "cwe-601" in vuln_type:
        # Open redirect requires that user-supplied URL is passed to redirect() without validation
        # If the code checks startswith("/") or validates the URL, it's NOT vulnerable
        has_redirect = "redirect(" in vuln_lower
        if not has_redirect:
            return False, "Code does not call redirect(). Must use redirect(user_input) for open redirect."
        # Check if URL validation is present
        has_url_validation = (
            "startswith(" in vuln_lower and ("/" in vuln_code or "http" in vuln_lower)
        ) or "urlparse" in vuln_lower or "is_safe_url" in vuln_lower
        patch_has_url_validation = (
            "startswith(" in patch_lower and ("/" in patch_code or "http" in patch_lower)
        ) or "urlparse" in patch_lower or "is_safe_url" in patch_lower
        if has_url_validation and patch_has_url_validation:
            return False, "Code still validates redirect URL (e.g., startswith('/')). Must remove URL validation to allow external redirects."

    # --- Generic: vuln code identical to patch code ---
    if vuln_code.strip() == patch_code.strip():
        return False, "Vulnerable code is identical to patched code. No vulnerability was injected."
    # Also check if only comments/whitespace differ (normalize both)
    if _normalize(vuln_code) == _normalize(patch_code):
        return False, "Vulnerable code is functionally identical to patched code (only comments differ). No real vulnerability was injected."

    return True, "Vulnerability pattern validated."


def _repair_vulnerable_code(
    patch_code: str,
    broken_vuln_code: str,
    intended_vuln: dict,
    diagnosis: str,
    llm_fn,
    attempt: int = 1,
) -> str:
    """
    Use LLM to repair generated vulnerable code that doesn't actually contain
    the intended vulnerability.
    
    Args:
        patch_code: The original safe/patched code
        broken_vuln_code: The generated code that failed validation
        intended_vuln: Dict with 'type', 'expected_pattern', etc.
        diagnosis: What's wrong with the current code
        llm_fn: LLM generation function
        attempt: Current attempt number (for prompt variation)
    
    Returns:
        Repaired vulnerable code string
    """
    vuln_type = intended_vuln.get("type", "unknown vulnerability")
    expected_pattern = intended_vuln.get("expected_pattern", "")
    pattern_guidance = _get_vuln_pattern_guidance(vuln_type)

    prompt = f"""You are a security researcher creating vulnerable code for testing.

The following code was supposed to contain a {vuln_type} vulnerability, but the vulnerability was NOT properly injected.

DIAGNOSIS: {diagnosis}

{pattern_guidance}

ORIGINAL SAFE CODE:
```python
{patch_code}
```

BROKEN VULNERABLE CODE (does NOT contain the vulnerability):
```python
{broken_vuln_code}
```

{f'EXPECTED VULNERABILITY PATTERN: {expected_pattern}' if expected_pattern else ''}

Fix the vulnerable code so it ACTUALLY contains the {vuln_type} vulnerability.
The fix must be MINIMAL — change only what's needed to introduce the vulnerability.
Keep the same structure, imports, function names, routes, and output format.

Return ONLY the corrected Python code, no explanations:
```python"""

    try:
        response = llm_fn(prompt)
        if not response:
            return broken_vuln_code

        # Extract code from response
        code = response.strip()
        # Remove markdown fences
        if "```python" in code:
            code = code.split("```python", 1)[1]
        if "```" in code:
            code = code.split("```", 1)[0]
        code = code.strip()

        # Remove thinking tags if present
        if "<think>" in code:
            think_end = code.find("</think>")
            if think_end != -1:
                code = code[think_end + len("</think>"):].strip()

        # Validate syntax
        try:
            ast.parse(code)
        except SyntaxError:
            return broken_vuln_code

        # Don't accept empty or trivially short code
        if len(code) < 20:
            return broken_vuln_code

        return code
    except Exception as e:
        logging.getLogger(__name__).warning(f"  [Repair] LLM repair failed: {e}")
        return broken_vuln_code


def run_promote_phase(prompts_dir: str, vuln_output_dir: str = "vaitp_dataset/vulnerable",
                      max_repair_attempts: int = 5, llm_fn=None):
    """
    Promote Phase: Extract the best validated vulnerable code from Phase 2 results
    and save it to vaitp_dataset/vulnerable/ so Phase 3 can test it.

    For each injectable file, picks the generated code with the highest validation
    score (SUCCESS > FAILURE) and saves it as the vulnerable version.
    
    NEW: After promotion, validates that each vulnerable file actually contains
    the intended vulnerability. If not, uses LLM calls to diagnose and repair
    the code, up to max_repair_attempts times.
    """
    console.print(Rule("[bold green]:rocket: Promote Phase: Saving Best Vulnerable Code to Disk[/bold green]"))

    gen_results_path = os.path.join(prompts_dir, "generated_results.pkl")
    analyzed_results_path = os.path.join(prompts_dir, "analyzed_results.pkl")

    # Try analyzed first, fall back to generated
    results_path = analyzed_results_path if os.path.exists(analyzed_results_path) else gen_results_path
    if not os.path.exists(results_path):
        console.print(f"[bold red]:x: No Phase 2 results found at {results_path}. Run Phase 2 first.[/bold red]")
        return []

    with open(results_path, "rb") as f:
        all_results = pickle.load(f)

    os.makedirs(vuln_output_dir, exist_ok=True)

    # Group results by file_name, pick the best for each
    from collections import defaultdict
    by_file = defaultdict(list)
    for record in all_results:
        by_file[record['file_name']].append(record)

    promoted = []
    for file_name, records in by_file.items():
        # Score: SUCCESS > FAILURE, prefer longer code (more complete)
        def score(r):
            s = 0
            status = r.get('static_confirmation_status', '')
            if 'SUCCESS' in str(status):
                s += 10
            code = r.get('generated_code', '')
            if code and code.strip() != r.get('original_code', '').strip():
                s += 5
            s += min(len(code) / 100, 5)  # Prefer longer (more complete) code
            return s

        records.sort(key=score, reverse=True)
        best = records[0]
        code = best.get('generated_code', '').strip()

        if not code or code == best.get('original_code', '').strip():
            console.print(f"  [yellow]⚠ {file_name}: No valid vulnerable code generated, skipping[/yellow]")
            continue

        # Clean markdown artifacts before saving
        code = clean_code(code)
        
        # Validate it's actually Python (not explanation text)
        try:
            ast.parse(code)
        except SyntaxError:
            console.print(f"  [yellow]⚠ {file_name}: Generated code has syntax errors, attempting deeper clean[/yellow]")
            # Try extracting code from markdown fences
            import re as _re
            fence_match = _re.search(r'```python\s*\n(.*?)```', code, _re.DOTALL)
            if fence_match:
                code = fence_match.group(1).strip()
            else:
                # Try finding the first 'from' or 'import' line and take everything from there
                lines = code.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith(('from ', 'import ', 'def ', 'class ', '#!')):
                        code = '\n'.join(lines[i:])
                        break
            try:
                ast.parse(code)
            except SyntaxError as e2:
                console.print(f"  [red]✗ {file_name}: Still has syntax errors after cleaning: {e2}[/red]")
                continue

        # Skip files whose Phase 2 evaluation flagged them as syntax errors
        status = best.get('static_confirmation_status', 'unknown')
        if 'Syntax Error' in str(status):
            console.print(f"  [red]✗ {file_name}: Phase 2 evaluation flagged as syntax error, skipping[/red]")
            continue

        out_path = os.path.join(vuln_output_dir, file_name)
        with open(out_path, 'w') as f:
            f.write(code + '\n')

        model = best.get('model_full_name', 'unknown')
        console.print(f"  [green]✓ {file_name}[/green] → {out_path} (model={model}, status={status})")
        promoted.append((file_name, best.get('intended_vuln', {})))
        # Trace the promotion reasoning
        from trace_diagram import get_tracer
        _tr = get_tracer()
        _tr.trace_info("Promote",
                       f"Selected {file_name}: model={model}, strategy={best.get('prompt_strategy', '?')}, "
                       f"status={status}, score={score(best):.1f}, "
                       f"candidates={len(records)}",
                       details={
                           'file': file_name,
                           'selected_model': model,
                           'selected_strategy': best.get('prompt_strategy'),
                           'validation_status': status,
                           'score': round(score(best), 1),
                           'total_candidates': len(records),
                           'code_length': len(code),
                           'scoring_explanation': (
                               'Score = +10 if validation SUCCESS, '
                               '+5 if code differs from original, '
                               '+up to 5 for code length (longer=more complete). '
                               'All candidates: [' + ", ".join(
                                   f'{r.get("prompt_strategy","?")}/{r.get("static_confirmation_status","?")}/{score(r):.1f}'
                                   for r in records
                               ) + ']'
                           ),
                       })

    console.print(f"\n  Promoted {len(promoted)}/{len(by_file)} files to {vuln_output_dir}")

    # --- Vulnerability Validation & Repair Loop ---
    # For each promoted file, validate that the vulnerable code actually contains
    # the intended vulnerability. If not, use LLM to diagnose and repair.
    if max_repair_attempts > 0 and promoted:
        console.print(Rule("[bold yellow]:wrench: Vulnerability Validation & Repair[/bold yellow]"))
        injectable_dir = os.path.join(os.path.dirname(vuln_output_dir), "injectable")

        repaired_count = 0
        valid_count = 0
        failed_validation = []

        for file_name, intended_vuln in promoted:
            vuln_path = os.path.join(vuln_output_dir, file_name)
            patch_path = os.path.join(injectable_dir, file_name)

            if not os.path.exists(patch_path):
                continue

            with open(vuln_path) as f:
                vuln_code = f.read()
            with open(patch_path) as f:
                patch_code = f.read()

            is_valid, diagnosis = _validate_vulnerability(vuln_code, patch_code, intended_vuln)

            if is_valid:
                valid_count += 1
                continue

            console.print(f"  [yellow]⚠ {file_name}: {diagnosis}[/yellow]")

            if llm_fn is None:
                failed_validation.append(file_name)
                continue

            # Attempt LLM repair
            current_code = vuln_code
            repaired = False
            for attempt in range(1, max_repair_attempts + 1):
                console.print(f"    [cyan]Repair attempt {attempt}/{max_repair_attempts}...[/cyan]", end=" ")
                new_code = _repair_vulnerable_code(
                    patch_code, current_code, intended_vuln, diagnosis, llm_fn, attempt
                )

                if new_code == current_code:
                    console.print("[red]no change[/red]")
                    continue

                # Validate the repaired code
                is_valid, new_diagnosis = _validate_vulnerability(new_code, patch_code, intended_vuln)
                if is_valid:
                    # Save repaired code
                    with open(vuln_path, 'w') as f:
                        f.write(new_code + '\n')
                    console.print(f"[green]✓ fixed[/green]")
                    repaired_count += 1
                    repaired = True
                    break
                else:
                    console.print(f"[yellow]still invalid: {new_diagnosis}[/yellow]")
                    current_code = new_code
                    diagnosis = new_diagnosis

            if not repaired:
                failed_validation.append(file_name)
                console.print(f"    [red]✗ Could not repair {file_name} after {max_repair_attempts} attempts[/red]")

        console.print(f"\n  Validation: {valid_count} valid, {repaired_count} repaired, {len(failed_validation)} unfixable")
        if failed_validation:
            console.print(f"  [red]Unfixable: {', '.join(failed_validation)}[/red]")

    return [f for f, _ in promoted] if promoted and isinstance(promoted[0], tuple) else promoted


def run_promote_all_phase(prompts_dir: str, vuln_output_dir: str = "vaitp_dataset/vulnerable"):
    """
    Promote ALL Phase 2 generated codes to disk for Phase 3 testing.
    
    Unlike run_promote_phase (which picks only the best variant per file),
    this saves every valid generated variant as a separate file so Phase 3
    can test each one independently.
    
    Naming convention: original_name__variant_N.py
    (e.g. flask_sqli_1__variant_0.py, flask_sqli_1__variant_1.py)
    
    Returns a list of all saved filenames.
    """
    console.print(Rule("[bold green]:rocket: Promote ALL Phase 2 Codes to Disk[/bold green]"))

    gen_results_path = os.path.join(prompts_dir, "generated_results.pkl")
    analyzed_results_path = os.path.join(prompts_dir, "analyzed_results.pkl")

    results_path = analyzed_results_path if os.path.exists(analyzed_results_path) else gen_results_path
    if not os.path.exists(results_path):
        console.print(f"[bold red]:x: No Phase 2 results found at {results_path}. Run Phase 2 first.[/bold red]")
        return []

    with open(results_path, "rb") as f:
        all_results = pickle.load(f)

    os.makedirs(vuln_output_dir, exist_ok=True)

    from collections import defaultdict
    by_file = defaultdict(list)
    for record in all_results:
        by_file[record['file_name']].append(record)

    all_saved = []
    skipped = 0
    for file_name, records in by_file.items():
        base_name = file_name.rsplit('.py', 1)[0]
        variant_idx = 0
        for record in records:
            code = record.get('generated_code', '').strip()
            if not code or code == record.get('original_code', '').strip():
                skipped += 1
                continue

            # Clean markdown artifacts
            code = clean_code(code)

            # Validate syntax
            try:
                ast.parse(code)
            except SyntaxError:
                import re as _re
                fence_match = _re.search(r'```python\s*\n(.*?)```', code, _re.DOTALL)
                if fence_match:
                    code = fence_match.group(1).strip()
                try:
                    ast.parse(code)
                except SyntaxError:
                    skipped += 1
                    continue

            # Skip syntax-error flagged results
            status = record.get('static_confirmation_status', 'unknown')
            if 'Syntax Error' in str(status):
                skipped += 1
                continue

            # Save with variant suffix
            variant_name = f"{base_name}__variant_{variant_idx}.py"
            out_path = os.path.join(vuln_output_dir, variant_name)
            with open(out_path, 'w') as f:
                f.write(code + '\n')

            model = record.get('model_full_name', 'unknown')
            console.print(f"  [green]✓ {variant_name}[/green] (model={model}, status={status})")
            all_saved.append(variant_name)
            variant_idx += 1

    console.print(f"\n  Saved {len(all_saved)} variants across {len(by_file)} files ({skipped} skipped)")
    return all_saved


def run_export_phase(args_or_config):
    """
    A dedicated phase to export all data from the database to CSV and Excel files.
    
    Args:
        args_or_config: Either argparse.Namespace (legacy) or dict (config-driven)
    """
    console.print(Rule("[bold blue]:bar_chart: VAITP: Exporting Results[/bold blue]"))

    if not os.path.exists(DB_PATH):
        console.print(f":x: [bold red]Error: Database file not found at {DB_PATH}. Cannot export.[/bold red]")
        return

    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * from comparative_analysis_runs", con)
        con.close()
        console.print(f":white_check_mark: Loaded {len(df)} records from the database for export.")
        
        # Convert config to args-like object if needed for backward compatibility
        if isinstance(args_or_config, dict):
            config = args_or_config
            # Create a minimal args-like object with export settings
            args = argparse.Namespace()
            export_config = config.get('export', {})
            args.save_excel = export_config.get('save_excel', config.get('save_excel', False))
            args.excel_per_model = export_config.get('excel_per_model', config.get('excel_per_model', False))
        else:
            args = args_or_config
        
        save_dataframes_to_files(df, args)

    except Exception as e:
        console.print(f"[bold red]❌ Error reading from database: {e}[/bold red]")            
            

def _config_to_args(config: dict, original_args: argparse.Namespace) -> argparse.Namespace:
    """
    Convert configuration dictionary back to args-like object for backward compatibility.
    
    This allows the existing phase functions to work unchanged while using config-driven execution.
    """
    # Start with original args and override with config values
    args = argparse.Namespace(**vars(original_args))
    
    # Map config keys back to argument names
    config_to_arg_mapping = {
        'phase': 'phase',
        'reasoning_model': 'model',
        'coders_to_run': 'coder',
        'strategies_to_run': 'strategy',
        'stage': 'stage',
        'save_excel': 'save_excel',
        'excel_per_model': 'excel_per_model',
        'expected_dir': 'expected_dir',
        'input_pickle': 'input_pickle',
        'num_gpus': 'num_gpus',
        'input_dataset_dir': 'path',
        'experiment_name': 'experiment_name',
        # DEPRECATED: gold_only and llm_only are no longer used (see --gold-only/--llm-only above)
        # 'gold_only': 'gold_only',
        # 'llm_only': 'llm_only',
        'max_iterations': 'max_iterations',
        'filter': 'filter',
        'skip_proven': 'skip_proven',
        'resume': 'resume',
        'ollama': 'ollama',
        'vertex': 'vertex',
        'vertex_config': 'vertex_config',
        'stream_llm': 'stream_llm',
        'experiment_name': 'experiment_name',
        'test_timeout': 'test_timeout',
        'phase3_test_all': 'phase3_test_all',
        'intended_vulnerability': 'intended_vulnerability',
        'trace_diagram': 'trace_diagram',
        'trace_detail_level': 'trace_detail_level',
    }
    
    # Apply config values to args
    for config_key, arg_name in config_to_arg_mapping.items():
        if config_key in config and config[config_key] is not None:
            value = config[config_key]
            # Convert phase to string for compatibility with main function comparisons
            if config_key == 'phase':
                value = str(value)
            setattr(args, arg_name, value)
    
    # Handle nested export settings
    if 'export' in config and isinstance(config['export'], dict):
        export_config = config['export']
        if 'save_excel' in export_config:
            setattr(args, 'save_excel', export_config['save_excel'])
        if 'excel_per_model' in export_config:
            setattr(args, 'excel_per_model', export_config['excel_per_model'])
    
    return args


def main():
    parser = argparse.ArgumentParser(description="VAITP Platform - Scalable Vulnerability Injection with side-proofable Exploitation")
    
    # Primary configuration argument
    parser.add_argument("--config", type=str, help="Path to YAML experiment configuration file")
    
    # GPU control
    parser.add_argument("--num-gpus", type=int, help="Limit number of GPUs to use")
    
    # All existing arguments remain as optional overrides
    parser.add_argument("--phase", choices=['1', '2', '3', 'full', 'promote', 'reanalyze', 'export'],
                        help=(
                            "Phase to run (can be overridden by config). Choices:\n"
                            "  1         - Generate injection plans: uses the reasoning LLM to analyze\n"
                            "              each source file and produce vulnerability injection prompts.\n"
                            "  2         - Execute coder models: runs coder LLMs to generate vulnerable\n"
                            "              and patched code variants from Phase 1 prompts. Use --stage\n"
                            "              to run only generate/analyze/evaluate sub-stages.\n"
                            "  promote   - Promote best Phase 2 outputs to vaitp_dataset/vulnerable/\n"
                            "              for Phase 3 verification.\n"
                            "  3         - Verify exploitability: runs each vuln/patch pair inside Docker\n"
                            "              containers using the Double-Check Methodology (functional +\n"
                            "              security checks). ALL plans are LLM-generated. Gold standard\n"
                            "              knowledge is seeded as reference material for the LLM planner.\n"
                            "  full      - Run the complete pipeline: Phase 1 → 2 → promote → 3.\n"
                            "  reanalyze - Re-run static/semantic analysis on existing Phase 2 results.\n"
                            "  export    - Export results to CSV/Excel."
                        ))
    parser.add_argument("path", nargs='?', default=None, help="Path to the directory of files (Required for Phase 1).")
    parser.add_argument("--model", choices=list(REASONING_MODELS.keys()), default=None)
    parser.add_argument("--coder", nargs='+', choices=list(CODER_MODELS.keys()) + ['all'], default=['all'])
    parser.add_argument(
        "--strategy",
        nargs='+',  
        choices=[s.name for s in PromptingStrategy] + ['all'],
        default=['all'],
        help="Specify one or more strategies to run."
    )
    parser.add_argument("--save-excel", action="store_true")

    parser.add_argument("--excel-per-model", action="store_true", help="Save a separate Excel file for each model's results.")
    
    parser.add_argument("--stage", choices=['generate', 'analyze', 'evaluate', 'all'], default=None,
                        help="Phase 2 sub-stage: 'generate' runs coder LLMs, 'analyze' runs static/semantic "
                             "analysis, 'evaluate' computes metrics, 'all' runs everything (default: all)")
    
    parser.add_argument("--input-pickle", type=str, default=None, help="Specify a specific .pkl file for the reanalyze phase.")

    parser.add_argument(
        "--expected-dir",
        type=str,
        default=None,
        help="Path to the directory with expected/solution code files. If provided, this code will be added to the database."
    )

    # Phase 3 specific arguments
    # DEPRECATED: --gold-only and --llm-only are no longer functional.
    # All Phase 3 tests now use the LLM planner with gold standard knowledge
    # seeded as reference material. Kept here for reference:
    #   parser.add_argument("--gold-only", action="store_true",
    #                       help="(Legacy, ignored) All Phase 3 tests now use the LLM planner. "
    #                            "Gold standard knowledge is seeded as reference material.")
    #   parser.add_argument("--llm-only", action="store_true",
    #                       help="(Legacy, ignored) All Phase 3 tests now use the LLM planner.")
    parser.add_argument("--max-iterations", type=int, default=None,
                        help="Phase 3: Max planner self-correction iterations per LLM test (default: 3)")
    parser.add_argument("--max-repair-attempts", type=int, default=5,
                        help="Promote: Max LLM repair attempts for non-vulnerable generated code (default: 5)")
    parser.add_argument("--filter", type=str, default=None,
                        help="Phase 3: Only run tests whose filename contains this substring (e.g. --filter flask)")
    parser.add_argument("--skip-proven", action="store_true",
                        help="Phase 3: Skip tests that already have a proven plan in generated_plans/exploited/")
    parser.add_argument("--resume", action="store_true",
                        help="Phase 3: Skip both proven and previously-failed tests (only run untested files)")
    parser.add_argument("--ollama", action="store_true",
                        help="Phase 3: Use Ollama backend instead of llama-cpp (faster startup, no GGUF needed)")
    parser.add_argument("--vertex", action="store_true",
                        help="Use Vertex AI backend (requires --vertex-config)")
    parser.add_argument("--vertex-config", type=str, default=None,
                        help="Path to Vertex AI YAML config (e.g. configs/config_deepseek.yaml)")
    parser.add_argument("--voting-config", type=str, default=None,
                        help="Path to a YAML config with a 'voting:' block. Enables the "
                             "jury (multiple juror models + judge) for allowlisted decisions "
                             "across phases (forwarded to Phase 3).")
    parser.add_argument("--stream-llm", action="store_true",
                        help="Phase 3: Show live LLM token output in a split terminal view")
    parser.add_argument("--test-timeout", type=int, default=0,
                        help="Phase 3: Per-test timeout in seconds; 0 = no limit (default: 0)")
    parser.add_argument("--phase3-test-all", action="store_true",
                        help="Phase 3: Test ALL Phase 2 generated codes, not just the promoted (best) ones. "
                             "Each variant is saved to vaitp_dataset/vulnerable/ and tested independently.")
    parser.add_argument("--intended-vulnerability", type=str, default=None,
                        help="Phase 1: Skip LLM vulnerability identification and use this vulnerability type "
                             "for all files (e.g. 'SQL Injection', 'OS Command Injection'). "
                             "Can also be set in YAML config as 'intended_vulnerability' with full dict.")
    
    # RAG index update control
    parser.add_argument("--no-rag-update", action="store_true",
                        help="Skip automatic RAG index update from the MySQL database on startup")
    parser.add_argument("--force-rag-update", action="store_true",
                        help="Force RAG index update even if the local index appears current")

    # Trace diagram arguments
    parser.add_argument("--trace-diagram", action="store_true",
                        help="Generate an HTML trace report of the execution flow for explainability")
    parser.add_argument("--trace-detail-level", choices=['minimal', 'standard', 'detailed', 'full'],
                        default=None,
                        help="Detail level for trace report: minimal (phases only), standard (+ LLM summaries), "
                             "detailed (+ prompt/response previews), full (complete prompts/responses)")

    args = parser.parse_args()

    # Defaults for deprecated flags removed from the parser (still referenced downstream)
    args.gold_only = False
    args.llm_only = False

    # Normalize --intended-vulnerability from CLI string to dict
    if getattr(args, 'intended_vulnerability', None) and isinstance(args.intended_vulnerability, str):
        args.intended_vulnerability = {"type": args.intended_vulnerability}

    # Load and merge configuration
    config = None
    if args.config:
        from configuration_manager import ConfigurationManager
        config_manager = ConfigurationManager()
        config = config_manager.load_config(args.config, args)
        config_manager.validate_config(config)
        
        # Additional phase-specific validation
        if config.get('phase'):
            config_manager.validate_phase_config(config, config['phase'])
        
        # Save experiment metadata for reproducibility
        results_dir = "results"  # Default results directory
        config_manager.save_experiment_metadata(config, results_dir)
        
        # Convert config to args-like object for backward compatibility
        args = _config_to_args(config, args)
    else:
        # Fallback to command-line only mode for backward compatibility
        if not args.phase:
            parser.error("--phase is required when not using --config")

    # Determine whether to pass config or args to phase functions
    phase_input = config if config else args
    
    # Initialize execution tracer
    from trace_diagram import init_tracer, get_tracer
    _trace_enabled = getattr(args, 'trace_diagram', False)
    _trace_detail = getattr(args, 'trace_detail_level', None) or 'standard'
    tracer = init_tracer(
        enabled=_trace_enabled,
        detail_level=_trace_detail,
        output_dir="results",
    )
    if _trace_enabled:
        logging.info("📊 Execution tracing enabled (detail=%s)", _trace_detail)
        _cfg_to_trace = config if config else vars(args)
        # Include the exact command used to invoke the framework
        import shlex
        _cfg_to_trace = dict(_cfg_to_trace)  # copy
        _cfg_to_trace['_command_line'] = ' '.join(shlex.quote(a) for a in sys.argv)
        tracer.trace_config_loaded(_cfg_to_trace)

    # Set module-level Ollama flag so all initialize_llm() calls use Ollama
    global USE_OLLAMA_BACKEND
    if getattr(args, 'ollama', False):
        USE_OLLAMA_BACKEND = True
        logging.info("🦙 Ollama backend enabled globally for all phases")

    # Set module-level streaming flag and initialize the split-terminal display
    global _STREAM_LLM
    if getattr(args, 'stream_llm', False):
        _STREAM_LLM = True
        from llm_stream_display import init_display
        init_display()

    # --- RAG Index Update ---
    # Automatically update the FAISS index from the MySQL database unless disabled.
    if not getattr(args, 'no_rag_update', False):
        try:
            from rag_updater import update_rag_index
            force = getattr(args, 'force_rag_update', False)
            update_rag_index(force=force)
        except Exception as e:
            logging.warning(f"RAG index update skipped: {e}")
    else:
        logging.info("RAG index update disabled (--no-rag-update)")

    if args.phase == '1':
        tracer.trace_phase_start("Phase 1 - Prompt Generation", {
            "model": getattr(args, 'model', None),
            "strategies": getattr(args, 'strategy', None),
        })
        run_phase1_generate_prompts(phase_input)
        tracer.trace_phase_end("Phase 1 - Prompt Generation")
    elif args.phase == '2':
        # Determine the correct prompts directory based on the model used in Phase 1
        prompts_dir = None
        if hasattr(args, 'coder') and args.coder:
            model_key = args.coder[0] if isinstance(args.coder, list) else args.coder
            experiment_name = getattr(args, 'experiment_name', None)
            
            # For phase2 experiments, look for corresponding Phase 1 directory
            if experiment_name and 'phase2' in experiment_name:
                # Map phase2 experiment names to phase1 directories
                if 'IEEE_DirectVsMetaRAG_phase2_deepthink' in experiment_name:
                    phase1_experiment = 'IEEE_DirectVsMetaRAG_phase1_deepthink'
                elif 'IEEE_DirectVsMetaRAG_phase2_llama' in experiment_name:
                    phase1_experiment = 'IEEE_DirectVsMetaRAG_phase1_llama'
                elif 'deepthink' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_deepthink'
                elif 'llama' in experiment_name:
                    phase1_experiment = 'CVE2023_phase1_llama'
                elif 'test_phase2_all_models_injectable' in experiment_name:
                    # For the test phase2 experiment, use the existing phase1 directory
                    phase1_experiment = 'test_phase1_injectable_dataset'
                    # Use llama-3.1-8b as the model key since that's what was used in phase1
                    model_key = 'llama-3.1-8b'
                else:
                    phase1_experiment = experiment_name.replace('phase2', 'phase1')
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, phase1_experiment)
            else:
                from config import get_model_specific_prompts_dir
                prompts_dir = get_model_specific_prompts_dir(model_key, experiment_name)
        
        # Use enhanced Phase 2 with vulnerability validation
        tracer.trace_phase_start("Phase 2 - Coder Execution", {
            "coders": getattr(args, 'coder', None),
            "strategies": getattr(args, 'strategy', None),
            "stage": getattr(args, 'stage', None),
        })
        run_phase2_execute_coders(args, prompts_dir)  # Pass prompts directory
        tracer.trace_phase_end("Phase 2 - Coder Execution")
    elif args.phase == 'reanalyze':
        tracer.trace_phase_start("Reanalyze")
        run_reanalysis_phase(phase_input)
        tracer.trace_phase_end("Reanalyze")
    elif args.phase == 'export':
        tracer.trace_phase_start("Export")
        run_export_phase(phase_input)
        tracer.trace_phase_end("Export")
    elif args.phase == 'promote':
        # Promote Phase: Save best Phase 2 vulnerable code to vaitp_dataset/vulnerable/
        experiment_name = getattr(args, 'experiment_name', None)
        model_key = args.model or 'llama-3.1-8b'
        from config import get_model_specific_prompts_dir
        p_dir = get_model_specific_prompts_dir(model_key, experiment_name)
        # Create LLM function for vulnerability repair
        _promote_llm_fn = None
        try:
            if getattr(args, 'ollama', False):
                _promote_llm_fn = create_ollama_wrapper(
                    args.model if hasattr(args, 'model') and args.model else 'deepseek-r1:14b',
                    stream_llm=_STREAM_LLM,
                )
        except Exception:
            pass
        _max_repair = getattr(args, 'max_repair_attempts', 5)
        promoted = run_promote_phase(p_dir, max_repair_attempts=_max_repair, llm_fn=_promote_llm_fn)

        # If phase3_test_all is set, also save all variants
        if getattr(args, 'phase3_test_all', False):
            print("\n--- Promote ALL: Saving all Phase 2 variants ---")
            all_variants = run_promote_all_phase(p_dir)
            promoted = all_variants

        # Copy injectable (patched) counterparts so Phase 3 can pair them
        injectable_dir = "vaitp_dataset/injectable"
        input_dir = getattr(args, 'path', None)
        if promoted and input_dir and os.path.isdir(input_dir):
            import shutil as _shutil
            os.makedirs(injectable_dir, exist_ok=True)
            if getattr(args, 'phase3_test_all', False):
                # For test-all mode: map variant names back to originals
                for variant_name in promoted:
                    if '__variant_' in variant_name:
                        original_base = variant_name.split('__variant_')[0] + '.py'
                    else:
                        original_base = variant_name
                    src = os.path.join(input_dir, original_base)
                    dst = os.path.join(injectable_dir, variant_name)
                    if os.path.exists(src) and not os.path.exists(dst):
                        _shutil.copy2(src, dst)
            else:
                for file_name in promoted:
                    src = os.path.join(input_dir, file_name)
                    dst = os.path.join(injectable_dir, file_name)
                    if os.path.exists(src) and not os.path.exists(dst):
                        _shutil.copy2(src, dst)

    elif args.phase in ('3', 'full'):
        # Verify Docker is running before entering Phase 3 (or the full pipeline
        # which ends with Phase 3).
        from docker_utils import check_docker_available
        if not check_docker_available():
            print("\n  \033[91mERROR: Docker is not running.\033[0m")
            print("  \033[93mPhase 3 requires Docker to execute tests inside containers.\033[0m")
            print("  \033[93mPlease start the Docker application and try again.\033[0m\n")
            sys.exit(1)

        # For 'full' phase: run Phase 1 → 2 → promote → 3 sequentially
        if args.phase == 'full':
            print("=== FULL PIPELINE: Phase 1 → Phase 2 → Promote → Phase 3 ===\n")
            tracer.trace_info("Orchestrator", "Full pipeline: Phase 1 → 2 → Promote → 3")

            # Ensure stage is set for Phase 2
            if not getattr(args, 'stage', None):
                args.stage = 'all'

            # Phase 1: Generate prompts (force regeneration in full pipeline)
            print("--- Phase 1: Generating injection plans ---")
            tracer.trace_phase_start("Phase 1 - Prompt Generation", {
                "model": getattr(args, 'model', None),
                "strategies": getattr(args, 'strategy', None),
                "input_dir": getattr(args, 'path', None),
            })
            if _STREAM_LLM:
                from llm_stream_display import get_display as _get_disp
                _d = _get_disp()
                if _d: _d.set_phase("Phase 1")
            run_phase1_generate_prompts(phase_input, force_regenerate=True)
            tracer.trace_phase_end("Phase 1 - Prompt Generation")

            # Phase 2: Execute coders
            print("\n--- Phase 2: Executing coder models ---")
            tracer.trace_phase_start("Phase 2 - Coder Execution")
            if _STREAM_LLM:
                _d = _get_disp()
                if _d: _d.set_phase("Phase 2")
            experiment_name = getattr(args, 'experiment_name', None)
            # Use the REASONING model key for prompts dir (Phase 1 saves prompts under reasoning model)
            reasoning_key = args.model if hasattr(args, 'model') and args.model else 'deepseek-r1:14b'
            from config import get_model_specific_prompts_dir
            p_dir = get_model_specific_prompts_dir(reasoning_key, experiment_name)
            run_phase2_execute_coders(args, p_dir)
            tracer.trace_phase_end("Phase 2 - Coder Execution")

            # Promote: Save best vulnerable code to disk
            # Clean vulnerable dir first so Phase 3 only tests files from THIS run
            vuln_dir = "vaitp_dataset/vulnerable"
            if os.path.isdir(vuln_dir):
                for old_f in os.listdir(vuln_dir):
                    if old_f.endswith('.py'):
                        os.remove(os.path.join(vuln_dir, old_f))
            print("\n--- Promote: Saving best vulnerable code ---")
            tracer.trace_phase_start("Promote")
            # Create LLM function for vulnerability repair during promotion
            _promote_llm_fn = None
            try:
                if getattr(args, 'ollama', False):
                    _ollama_wrapper = create_ollama_wrapper(
                        args.model if hasattr(args, 'model') and args.model else 'deepseek-r1:14b',
                        stream_llm=_STREAM_LLM,
                    )
                    # Wrap to match expected signature (prompt -> str)
                    def _promote_llm_fn(prompt, _w=_ollama_wrapper):
                        result = _w(prompt)
                        choices = result.get('choices', [])
                        return choices[0].get('text', '') if choices else ''
            except Exception as e:
                print(f"  Warning: Could not create LLM for repair: {e}")

            _max_repair = getattr(args, 'max_repair_attempts', 5)
            promoted = run_promote_phase(p_dir, max_repair_attempts=_max_repair, llm_fn=_promote_llm_fn)
            # Trace promote details
            if promoted:
                for fname in promoted:
                    tracer.trace_info("Promote", f"Promoted: {fname}")
            else:
                tracer.trace_info("Promote", "No files promoted (all failed validation or generation)")

            # --- phase3_test_all: save ALL variants instead of just the best ---
            if getattr(args, 'phase3_test_all', False):
                print("\n--- Promote ALL: Saving all Phase 2 variants for Phase 3 ---")
                all_variants = run_promote_all_phase(p_dir)
                # Use the variant list as the promoted list for injectable copying
                promoted = all_variants

            # Always copy injectable (patched) counterparts so Phase 3 can pair them.
            # Also, when promote fails for a file, copy the injectable code as a
            # "vulnerable" placeholder — Phase 3's LLM repair loop will inject the
            # actual vulnerability.
            injectable_dir = "vaitp_dataset/injectable"
            input_dir = getattr(args, 'path', None)
            if input_dir and os.path.isdir(input_dir):
                import shutil as _shutil
                os.makedirs(injectable_dir, exist_ok=True)
                os.makedirs(vuln_dir, exist_ok=True)

                # Get all target files from the input directory
                target_files = [f for f in os.listdir(input_dir) if f.endswith('.py')]
                promoted_names = set(promoted) if promoted else set()

                if getattr(args, 'phase3_test_all', False):
                    # For test-all mode: each variant needs its own injectable counterpart
                    # Variant names are like base_name__variant_N.py → map back to original
                    for variant_name in promoted_names:
                        # Extract original base name: "flask_sqli_1__variant_0.py" → "flask_sqli_1.py"
                        if '__variant_' in variant_name:
                            original_base = variant_name.split('__variant_')[0] + '.py'
                        else:
                            original_base = variant_name
                        src = os.path.join(input_dir, original_base)
                        dst = os.path.join(injectable_dir, variant_name)
                        if os.path.exists(src) and not os.path.exists(dst):
                            _shutil.copy2(src, dst)
                    # Also copy originals for any non-variant files
                    for file_name in target_files:
                        src = os.path.join(input_dir, file_name)
                        dst = os.path.join(injectable_dir, file_name)
                        if os.path.exists(src) and not os.path.exists(dst):
                            _shutil.copy2(src, dst)
                else:
                    for file_name in target_files:
                        # Always copy injectable counterpart
                        src = os.path.join(input_dir, file_name)
                        dst = os.path.join(injectable_dir, file_name)
                        if os.path.exists(src) and not os.path.exists(dst):
                            _shutil.copy2(src, dst)

                        # If promote failed for this file, copy injectable as vulnerable
                        # placeholder so Phase 3 has something to work with
                        vuln_dst = os.path.join(vuln_dir, file_name)
                        if file_name not in promoted_names and not os.path.exists(vuln_dst):
                            _shutil.copy2(src, vuln_dst)
                            print(f"  Fallback: copied {file_name} as vulnerable placeholder (Phase 3 will repair)")

            if not promoted:
                print("No files promoted. Fallback copies created for Phase 3 repair.")

            print("\n--- Phase 3: Verification ---")
            tracer.trace_phase_end("Promote")
            tracer.trace_phase_start("Phase 3 - Verification")

        # Phase 3: Full dataset verification (Double-Check Methodology)
        # Delegates to run_phase3.py which handles gold standard + LLM plans
        # Shut down stream display before spawning Phase 3 subprocess
        # (Phase 3 will init its own display if --stream-llm is passed)
        if _STREAM_LLM:
            from llm_stream_display import shutdown_display
            shutdown_display()
        import subprocess as _sp
        phase3_args = [sys.executable, "run_phase3.py"]
        # Forward relevant args
        if hasattr(args, 'model') and args.model:
            model = args.model if isinstance(args.model, str) else args.model[0] if args.model else None
            if model:
                phase3_args.extend(["--model", model])
        if hasattr(args, 'context') and args.context:
            phase3_args.extend(["--context", str(args.context)])
        if getattr(args, 'max_iterations', None):
            phase3_args.extend(["--max-iterations", str(args.max_iterations)])
        if getattr(args, 'max_repair_attempts', None):
            phase3_args.extend(["--max-repair-attempts", str(args.max_repair_attempts)])
        if getattr(args, 'filter', None):
            phase3_args.extend(["--filter", args.filter])
        if getattr(args, 'skip_proven', False):
            phase3_args.append("--skip-proven")
        if getattr(args, 'resume', False):
            phase3_args.append("--resume")
        if getattr(args, 'ollama', False):
            phase3_args.append("--ollama")
        if getattr(args, 'vertex', False):
            phase3_args.append("--vertex")
        if getattr(args, 'vertex_config', None):
            phase3_args.extend(["--vertex-config", args.vertex_config])
        if getattr(args, 'voting_config', None):
            phase3_args.extend(["--voting-config", args.voting_config])
        if getattr(args, 'stream_llm', False):
            phase3_args.append("--stream-llm")
        if getattr(args, 'experiment_name', None):
            phase3_args.extend(["--experiment-name", args.experiment_name])
        if getattr(args, 'test_timeout', 0) > 0:
            phase3_args.extend(["--test-timeout", str(args.test_timeout)])
        if getattr(args, 'phase3_test_all', False):
            phase3_args.append("--phase3-test-all")
        # No --filter needed: the cleanup before promote ensures only
        # files from THIS run exist in vaitp_dataset/vulnerable/.
        tracer.trace_info("Orchestrator", f"Phase 3 launched as subprocess: {' '.join(phase3_args)}")
        # Save trace events so Phase 3 subprocess can load and extend them
        _trace_events_path = None
        if tracer.enabled:
            _trace_events_path = os.path.join("results", ".trace_events_handoff.json")
            tracer.save_events(_trace_events_path)
            tracer._phase3_will_render = True  # Phase 3 will render the combined trace
        # Forward trace args to Phase 3 subprocess
        if getattr(args, 'trace_diagram', False):
            phase3_args.append("--trace-diagram")
        if getattr(args, 'trace_detail_level', None):
            phase3_args.extend(["--trace-detail-level", args.trace_detail_level])
        if _trace_events_path:
            phase3_args.extend(["--trace-events-file", _trace_events_path])
        sys.stdout.flush()
        result = _sp.run(phase3_args)
        sys.exit(result.returncode)

if __name__ == "__main__":
    console.clear()
    if sys.stdout.isatty():
       banner_matrix_final()
    with open(os.devnull, 'w') as f, contextlib.redirect_stderr(f):
        try:
            main()
        finally:
            # Render trace diagram if enabled.
            # Skip if Phase 3 was launched as subprocess — it renders the combined trace.
            try:
                from trace_diagram import get_tracer
                _t = get_tracer()
                if _t.enabled and not _t._phase3_will_render:
                    trace_path = _t.render()
                    if trace_path:
                        print(f"\n📊 Execution trace saved to: {trace_path}")
            except Exception as _te:
                logging.warning(f"Could not render trace diagram: {_te}")
            if _STREAM_LLM:
                from llm_stream_display import shutdown_display
                shutdown_display()