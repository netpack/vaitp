import os

def is_safe_path(base_path, user_input):
    # Resolve the absolute path of the user input
    user_input_abs = os.path.abspath(user_input)
    # Resolve the base path to ensure it's an absolute path
    base_path_abs = os.path.abspath(base_path)
    
    # Check if the resolved user input path starts with the base path
    return os.path.commonpath([base_path_abs]) == os.path.commonpath([base_path_abs, user_input_abs])

def execute_script(script_path):
    base_path = '/path/to/safe/scripts'  # Define a safe base path for scripts
    if is_safe_path(base_path, script_path):
        # Execute the script if it's safe
        exec(open(script_path).read())
    else:
        raise ValueError("Attempted to execute a script outside of the safe directory.")

# Example usage
try:
    execute_script('user_input_script.py')  # Replace with actual user input
except Exception as e:
    print(f"Error: {e}")