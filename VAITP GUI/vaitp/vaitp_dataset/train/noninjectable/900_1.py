import subprocess

def execute_macro(macro_content, context):
    # Instead of eval, use a safer method like subprocess if external commands are needed
    try:
        result = subprocess.run(macro_content, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"



# Example usage
user_input = "ls -l" # A safe command
context = {}  # Context for execution
result = execute_macro(user_input, context)
print(result)