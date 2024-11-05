def _is_jailbreak(input_data):
    # Patched code that prevents arbitrary code execution
    if isinstance(input_data, str) and input_data.isalnum():
        return True
    return False