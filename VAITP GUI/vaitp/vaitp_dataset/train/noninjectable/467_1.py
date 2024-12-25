import os
import tempfile

def create_temp_file(data):
    # Create a temporary file insecurely
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        temp_file.write(data.encode())
        temp_file.close()
        # Do something with the temp file
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if temp_file and hasattr(temp_file, 'name') and os.path.exists(temp_file.name):
            os.remove(temp_file.name)  # Attempt to remove the file