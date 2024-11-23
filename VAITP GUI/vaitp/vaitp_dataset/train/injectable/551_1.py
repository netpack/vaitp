import tempfile
import os
import stat

def secure_temp_file():
    # Create a secure temporary file with restricted permissions
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    os.chmod(temp_file.name, stat.S_IRUSR | stat.S_IWUSR)  # Only allow the owner to read and write
    return temp_file.name

# Example usage
temp_file_path = secure_temp_file()
with open(temp_file_path, 'w') as f:
    f.write("Secure temporary file content.")

# Ensure to clean up the temporary file after use
os.remove(temp_file_path)