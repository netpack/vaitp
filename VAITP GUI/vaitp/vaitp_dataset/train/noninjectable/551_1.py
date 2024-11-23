import tempfile

def insecure_temp_file():
    # Create a temporary file without proper permission management
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    return temp_file.name

# Example usage
temp_file_path = insecure_temp_file()
with open(temp_file_path, 'w') as f:
    f.write("Insecure temporary file content.")

# Note: This file can be accessed by other users on the system before it's deleted.