import os
import tempfile

def create_makefile_conf():
    # Create a temporary file insecurely
    temp_file_name = tempfile.mktemp(prefix='Makefile-conf-')
    with open(temp_file_name, 'w') as temp_file:
        temp_file.write("# Makefile configuration\n")
    
    # Permissions are not set, leaving it vulnerable
    # Local users could modify this file during a time window
    
    # Now, use the temporary file
    with open(temp_file_name, 'r') as file:
        print(file.read())
    
    # Clean up the temporary file
    os.remove(temp_file_name)

create_makefile_conf()