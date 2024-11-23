# Vulnerable code that allows execution of arbitrary code
def execute_code(code):
    exec(code)

# Example of potentially malicious code
malicious_code = "__import__('os').system('echo Vulnerable!')"

# Execute the malicious code
execute_code(malicious_code)