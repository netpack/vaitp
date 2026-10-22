from contextlib import contextmanager
import gc, ast, difflib, re, logging
from rich.logging import RichHandler # type: ignore

HARMFUL_COMMAND_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"mkfs",
    r"dd\s+if=/dev/zero",
    # more patterns if needed
]

def contains_harmful_payload(code_string: str) -> bool:
    for pattern in HARMFUL_COMMAND_PATTERNS:
        if re.search(pattern, code_string):
            logging.warning(f"Harmful pattern '{pattern}' detected in generated code.")
            return True
    return False

def sanitize_generated_code(code_string: str) -> str:
    # Basic sanitization: replace common harmful payloads with a benign one
    # This is a simple approach; more sophisticated context-aware replacement might be needed
    sanitized_code = code_string
    if "rm -rf /" in sanitized_code: # Be careful with overly broad replaces
         # This might be too naive if "rm -rf /" appears in comments or strings not meant for execution
         # A more robust way would be to identify if it's part of an actual command string
         # For now, we'll assume it's a payload example from the LLM.
        logging.warning("Replacing 'rm -rf /' with a benign placeholder.")
        sanitized_code = sanitized_code.replace("rm -rf /", "echo 'simulated harmful payload'")
    # Add more specific replacements if needed
    return sanitized_code
def check_vulnerabilities_with_bandit(code):
    from bandit.core import config, manager # type: ignore
    conf = config.BanditConfig()
    mngr = manager.BanditManager(conf, "file")
    temp_file = "temp_scan.py"
    with open(temp_file, "w") as f:
        f.write(code)
    mngr.discover_files([temp_file])
    mngr.run_tests()
    results = [issue.text for issue in mngr.results]
    return results

def clear_memory():
    gc.collect()

def load_file_content(file_path):
    """
    Load file content safely, returning None if file doesn't exist.
    This allows the framework to skip expected file logic gracefully.
    """
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        logging.debug(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.warning(f"Error reading file {file_path}: {e}")
        return None

def remove_comments(python_code: str) -> str:
    """
    Removes single-line Python comments and resulting empty lines.
    """
    no_hash_comments = re.sub(r"#.*$", "", python_code, flags=re.MULTILINE)
    # Remove lines that are now empty or contain only whitespace
    cleaned_lines = [line for line in no_hash_comments.splitlines() if line.strip()]
    return "\n".join(cleaned_lines)

def compute_diff(expected, generated):
    diff = difflib.unified_diff(
        remove_comments(expected).splitlines(),
        remove_comments(generated).splitlines(),
        lineterm=""
    )
    return "\n".join(diff)

def is_output_matching(expected_versions, generated):
    generated_no_comments = remove_comments(generated).strip()
    for expected in expected_versions:
        if remove_comments(expected).strip() == generated_no_comments:
            return True, expected
    return False, ""

def validate_python_script(script: str) -> bool:
    if len(script.encode('utf-8')) > 512_000:
        raise ValueError("Script exceeds 512 KB in size.")
    try:
        ast.parse(script)
    except SyntaxError:
        raise ValueError("Script contains invalid Python syntax.")
    return True

def remove_trailing_explanations(code_str: str) -> str:
    parts = code_str.rsplit("```", 1)
    return parts[0].rstrip()

def clean_code(generated_code: str) -> str:
    """
    A safer and more robust function to clean generated code.
    Avoids regex patterns known to cause catastrophic backtracking.
    """
    if not isinstance(generated_code, str):
        return ""

    code = generated_code.strip()

    # Step 1: Handle and remove markdown fences
    if code.startswith("```python"):
        code = code[len("```python"):].lstrip()
    elif code.startswith("```"):
        code = code[3:].lstrip()
    if code.endswith("```"):
        code = code[:-3].rstrip()
        
    code = code.strip()

    # Step 1b: If there's still a ``` fence in the middle (LLM output two code blocks),
    # truncate at the first ``` that appears after at least some code lines.
    lines_check = code.split('\n')
    code_started = False
    for i, line in enumerate(lines_check):
        stripped = line.strip()
        if not code_started and stripped and not stripped.startswith('```'):
            code_started = True
        if code_started and stripped.startswith('```'):
            code = '\n'.join(lines_check[:i])
            break

    # Step 2: Handle and remove potential surrounding docstrings
    if code.startswith(('"""', "'''")):
        quote_type = code[:3]
        if code.endswith(quote_type):
            code = code[3:-3].strip()

    # Step 3: Remove trailing conversational text.
    # We will do this line by line for safety.
    lines = code.split('\n')
    cleaned_lines = []
    stop_phrases = ["Snippet:", "Explanation:", "The code above", "This script",
                    "I've modified", "I have modified", "I've added", "I have added",
                    "I've introduced", "I have introduced", "I've changed", "I have changed",
                    "This makes the code", "This introduces", "This creates",
                    "The vulnerability", "The modified code", "Note:", "Note that",
                    "Here's what", "Here is what", "Changes made:", "Key changes:",
                    "In this version", "In the modified"]
    for line in lines:
        # Check if a stop phrase (case-insensitive) is in the line
        if any(phrase.lower() in line.lower() for phrase in stop_phrases):
            break # Stop processing any further lines
        cleaned_lines.append(line)
    
    code = '\n'.join(cleaned_lines)

    # Step 3b: Fallback — if trailing non-Python text survived, truncate after
    # the last line that looks like valid Python (indented code, blank, or comment).
    # This catches any explanation text the stop phrases missed.
    lines = code.split('\n')
    last_python_idx = len(lines) - 1
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if not stripped:
            continue  # blank lines are fine
        # Lines that are clearly Python: start with indent, keyword, decorator, comment, or string
        if (lines[i][0] in (' ', '\t', '#', '@')
            or stripped.startswith(('import ', 'from ', 'def ', 'class ', 'if ', 'else',
                                    'elif ', 'for ', 'while ', 'try:', 'except', 'finally',
                                    'with ', 'return ', 'raise ', 'pass', 'break', 'continue',
                                    'yield ', 'assert ', 'global ', 'nonlocal '))
            or stripped.endswith((':', ')', ']', '}', ',', '\\'))
            or '=' in stripped or '(' in stripped):
            last_python_idx = i
            break
    code = '\n'.join(lines[:last_python_idx + 1])

    # Step 4: Final cleanup of any remaining whitespace
    return code.strip()

def compute_dynamic_reward(vuln_type, exec_output):
    if "successful" in exec_output.lower() and "not" not in exec_output.lower():
        return 1.0  # full reward if dynamic exploitation works
    return 0.0

def extract_routes_and_params(code: str):
    """
    Extracts all Flask routes (from @app.route(...)) and all parameter names
    used in request.args.get(...) calls from the provided code.

    Returns:
        routes (list of str): A list of all routes found.
        params (list of str): A list of unique parameter names.
    """
    # Find all routes from @app.route decorators.
    route_pattern = r"@app\.route\(\s*['\"]([^'\"]+)['\"]\s*\)"
    routes = re.findall(route_pattern, code)

    print(f'Found routes: {routes}')
    
    # Find all parameter names from request.args.get(...) calls.
    param_pattern = r"request\.args\.get\(\s*['\"]([^'\"]+)['\"]"
    params = re.findall(param_pattern, code)
    params = list(set(params))  # remove duplicates

    print(f'Found parameters: {params}')

    return routes, params

def setup_logging():
    logging.basicConfig(
        level="INFO",
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("orchestrator_run.log"),
            RichHandler(rich_tracebacks=True, show_path=False, markup=True)
        ]
    )
    logger = logging.getLogger("rich")

    # Write the exact command used to invoke this script as the first line of the log
    import sys, shlex
    cmd_line = " ".join(shlex.quote(a) for a in sys.argv)
    with open("orchestrator_run.log", "r+") as f:
        existing = f.read()
        f.seek(0)
        f.write(f"$ {cmd_line}\n{existing}")

    return logger

@contextmanager
def suppress_specific_logger(logger_name: str):
    """
    A context manager to temporarily disable a specific logger by name.
    """
    logger = logging.getLogger(logger_name)
    original_level = logger.level
    logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        logger.setLevel(original_level)