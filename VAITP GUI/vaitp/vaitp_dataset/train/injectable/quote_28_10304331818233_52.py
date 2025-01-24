import os
import tempfile
import uuid

def random_name():
    temp_file_name = f"{uuid.uuid4()}"
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as temp_file:
        temp_file.write("print('Hello from a safe temporary file')")
    
    try:
        os.chmod(temp_file.name, 0o700)
        os.system(f"python {temp_file.name}")
    finally:
      os.unlink(temp_file.name)

random_name()
