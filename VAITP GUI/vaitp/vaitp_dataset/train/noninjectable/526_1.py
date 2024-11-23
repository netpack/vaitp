def execute_user_code(user_code):
    # This function demonstrates the vulnerability by executing arbitrary user-provided code
    # without any restrictions, leading to potential arbitrary code execution.
    exec(user_code)  # Dangerous: executes any code passed to it

# Example usage
user_code = "import os; os.system('echo Vulnerable!')"  # This could execute arbitrary commands
execute_user_code(user_code)