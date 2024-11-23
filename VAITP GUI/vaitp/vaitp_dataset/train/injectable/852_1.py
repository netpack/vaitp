def safe_execute_script(user, script, allowed_scripts):
    # Check if the user has the necessary permissions
    if not user.has_permission('execute_scripts'):
        raise PermissionError("User  does not have permission to execute scripts.")

    # Validate the script against a list of allowed scripts
    if script not in allowed_scripts:
        raise ValueError("Script execution is not allowed.")

    # Execute the script in a safe context
    try:
        exec(script)  # Be cautious with exec, ensure it's safe
    except Exception as e:
        raise RuntimeError(f"Script execution failed: {e}")

# Example usage
allowed_scripts = [
    'print("Hello, world!")',
    'x = 5\nprint(x * 2)'
]

user = get_current_user()  # Assume this function retrieves the current user

# Example of a script that could be injected
user_input_script = 'print("Injected code")'  # This should be sanitized or restricted

# Attempt to safely execute the user input script
try:
    safe_execute_script(user, user_input_script, allowed_scripts)
except (PermissionError, ValueError, RuntimeError) as e:
    print(f"Error: {e}")