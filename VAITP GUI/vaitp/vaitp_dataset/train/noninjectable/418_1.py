def _is_jailbreak(input_data):
    # Vulnerable code that allows arbitrary code execution
    exec(input_data)  # This line is the source of the vulnerability
    return True