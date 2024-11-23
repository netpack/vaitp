import os

def execute_python_code(code, basename):
    # Vulnerable code: no sanitization of the basename
    file_path = os.path.join("workspace", basename)

    with open(file_path, 'w') as f:
        f.write(code)

    # Execute the code in a sandboxed environment (e.g., docker)
    # Here you would add the logic to run the code inside a docker container