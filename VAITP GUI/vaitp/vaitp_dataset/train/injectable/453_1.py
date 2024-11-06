import os
import tempfile

def process_file(file_path):
    # Create a temporary file in a secure manner
    with tempfile.NamedTemporaryFile(delete=False, dir='/secure/temp/dir') as temp_file:
        try:
            with open(file_path, 'r') as original_file:
                data = original_file.read()
                # Write data to the temporary file
                temp_file.write(data.encode())
        except Exception as e:
            # Handle exceptions appropriately
            print(f"Error processing file: {e}")
    # Further processing...