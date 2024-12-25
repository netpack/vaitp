import os
import uuid

def execute_python_code(code, basename):
    # Generate a unique filename to prevent path traversal and file overwriting
    unique_filename = str(uuid.uuid4()) + "_" + basename.replace("..", "").replace("/", "").replace("\\", "")
    file_path = os.path.join("workspace", unique_filename)


    with open(file_path, 'w') as f:
        f.write(code)

    # Execute the code in a sandboxed environment (e.g., docker)
    # Here you would add the logic to run the code inside a docker container