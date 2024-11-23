def execute_user_script(script):
    # Vulnerable code that executes arbitrary user scripts without validation
    exec(script)

# Example usage
user_script = "import os; os.system('echo Vulnerable!')"  # This could execute arbitrary commands
execute_user_script(user_script)

malicious_script = "__import__('os').system('rm -rf /')"  # This could be used for malicious actions
execute_user_script(malicious_script)