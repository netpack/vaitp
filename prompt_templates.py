PROMPT_TEMPLATES = {
    "prompts": [
        (
            "You are an expert security prompt engineer. Your task is to write a set of instructions for a Coder LLM. "
            "Do NOT write Python code yourself. Your ONLY output should be a numbered list of 7 instructions. "
            "Based on the source code and vulnerability details provided, generate the 7-point instruction list for the Coder LLM.\n\n"
            "CRITICAL CONTEXT: The vulnerable code will be tested in a Docker container. Exploitation is proved by "
            "the creation of a specific file (e.g., /tmp/pwned). The PATCHED code (original) must NOT create this file. "
            "This differential is how we verify the vulnerability exists and the patch works.\n\n"
            "The instructions are:\n"
            "1. **Target:** The function and line to modify.\n"
            "2. **Vulnerability:** The vulnerability to inject: `{vulnerability_type}`.\n"
            "3. **Change:** The exact code modification required. For the pattern `{expected_pattern}`, be explicit "
            "(e.g., 'Change `shell=False` to `shell=True`'). Include the side-effect file creation mechanism.\n"
            "4. **Validation:** Instructions on what validation to bypass or remove.\n"
            "5. **Observability:** Instructions to print command `stdout` and `stderr` with `STDOUT_VULNERABLE:` and `STDERR_VULNERABLE:` prefixes.\n"
            "6. **Minimality:** An instruction to only make minimal necessary changes.\n"
            "7. **Format:** An instruction to return only the full, raw, modified Python code."
            )
    ]
}

#meta-prompt + RAG w/ k=3 ## OLD META-PROMPT:
# "Analyze the following source code and propose a vulnerability injection prompt that instructs a model to modify the code "
# "in order to introduce a specific vulnerability. The vulnerability prompt should be tailored to the context of the code; "
# "for example, if the code validates URLs and makes HTTP requests (e.g., using the requests library), "
# "your prompt might target a Server-Side Request Forgery (SSRF) vulnerability by instructing to bypass URL validation—specifically, "
# "by removing or commenting out calls to any URL validation functions—and by altering HTTP request parameters (such as removing the allow_redirects=False parameter). "
# "Ensure that your proposed prompt explains that the modifications should be minimal (only where necessary to introduce the vulnerability) "
# "and that the original validation functions should remain in the code but not be invoked. "
# "When generating the task prompt, pay close attention to the 'expected_pattern' of the intended vulnerability. If the pattern mentions a specific parameter change (e.g., 'shell=True' for subprocess, or removing a specific validation function), ensure the task prompt for the Coder LLM explicitly includes this specific instruction for modification."
# "The prompt should be generic enough to be adapted for other vulnerabilities based on different input code, and it should instruct the model to return only the full modified code."
# "The focus should be on creating the exploitable condition, providing a benign payload (e.g.: whoami) within the modified code itself."