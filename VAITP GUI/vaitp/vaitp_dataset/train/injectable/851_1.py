import os

def execute_python_code(code, basename):
    # Sanitize the basename to prevent path traversal
    safe_basename = os.path.basename(basename)
    safe_path = os.path.join("workspace", safe_basename)

    # Ensure the file is being created within the workspace directory
    if not safe_path.startswith(os.path.join(os.getcwd(), "workspace")):
        raise ValueError("Invalid file path")

    with open(safe_path, 'w') as f:
        f.write(code)

    # Execute the code in a sandboxed environment (e.g., docker)
    # Here you would add the logic to run the code inside a docker container