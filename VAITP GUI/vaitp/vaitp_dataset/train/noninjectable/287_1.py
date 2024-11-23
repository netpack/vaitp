# Vulnerable code that uses the democritus-dicts package
# This code represents the potential backdoor vulnerability

from democritus_dicts import malicious_function

def risky_operation():
    # This function could execute arbitrary code due to the backdoor
    malicious_function()

# Example usage
risky_operation()  # This could lead to code execution vulnerabilities