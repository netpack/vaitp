import os
import tempfile
import stat

def create_makefile_conf():
    # Create a temporary file securely
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_name = temp_file.name
        temp_file.write(b"# Makefile configuration\n")
    
    # Set the intended ownership and permissions
    os.chmod(temp_file_name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # rw-r--r--
    
    # Now, safely use the temporary file
    try:
        with open(temp_file_name, 'r') as file:
            print(file.read())
    finally:
        os.remove(temp_file_name)  # Clean up the temporary file

create_makefile_conf()