import os

def execute_librelogo_script(script_name):
    # This function simulates executing a LibreLogo script without proper validation
    # Vulnerable to path traversal due to lack of checks
    script_path = f"C:\\Program Files\\LibreOffice\\share\\librelogo\\{script_name}.py"
    
    # Execute the script directly
    exec(open(script_path).read())

# Example of a potentially malicious filename
malicious_script = "C:\\Program Files\\LibreOffice\\share\\librelogo\\..\\..\\..\\..\\..\\..\\Windows\\System32\\malicious_script.py"

# Execute the script, which could lead to arbitrary code execution
execute_librelogo_script(malicious_script)