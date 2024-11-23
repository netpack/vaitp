# Example of a fix for CVE-2008-5102 in PythonScripts

def safe_execute(script):
    # Limit the capabilities of the executed script
    allowed_builtins = {
        'len': len,
        'str': str,
        'int': int,
        # Add other safe built-in functions as needed
    }
    
    # Define a restricted execution environment
    exec_globals = {'__builtins__': allowed_builtins}
    
    try:
        exec(script, exec_globals)
    except Exception as e:
        # Handle exceptions safely
        print(f"An error occurred: {e}")

# Example usage
user_script = """
# This script should be limited in functionality
result = len("Hello, World!")
"""

safe_execute(user_script)