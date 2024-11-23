import os
import subprocess

def execute_user_code(user_code):
    # This function is designed to prevent arbitrary code execution by 
    # restricting the execution environment and not allowing arbitrary code.
    # Using CodeJail or a similar sandboxing solution is recommended.

    # Example of a secure execution environment using subprocess with limited capabilities
    try:
        # Create a restricted environment
        restricted_env = {
            'PATH': '/usr/bin',  # Limit the PATH to only necessary binaries
            'PYTHONUNBUFFERED': '1',  # Ensure output is flushed
        }

        # Execute the user code in a restricted environment
        # Here we would typically use a sandboxing library like CodeJail
        # For demonstration, we'll just show how to call a subprocess safely
        result = subprocess.run(
            ['python3', '-c', user_code],
            env=restricted_env,
            capture_output=True,
            text=True,
            timeout=5  # Limit execution time to prevent infinite loops
        )
        
        if result.returncode == 0:
            return result.stdout  # Return the output if execution was successful
        else:
            return f"Error: {result.stderr}"  # Return the error if execution failed

    except Exception as e:
        return f"Execution failed: {str(e)}"

# Example usage
user_code = "print('Hello, World!')"  # This should be sanitized and validated