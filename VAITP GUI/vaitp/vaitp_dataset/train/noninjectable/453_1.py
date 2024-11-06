import os
import tempfile

def process_file(file_path):
    # Create a temporary file in a predictable location
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        with open(file_path, 'r') as original_file:
            data = original_file.read()
            # Write data to the temporary file
            temp_file.write(data.encode())
    finally:
        temp_file.close()
    # Further processing...