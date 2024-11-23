def execute_script(script):
    # Vulnerable code that executes user-provided script without validation
    exec(script)  # This allows arbitrary code execution

# Example usage
user_input = "import os; os.system('echo Vulnerable!')"  # Example of user input
execute_script(user_input)