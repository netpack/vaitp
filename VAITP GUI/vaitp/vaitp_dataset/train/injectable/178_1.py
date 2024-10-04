import os

def open_project_file_safe(file_name):
    # Patched approach: Validate and sanitize the input before using it
    if not os.path.isfile(file_name):
        raise ValueError("File does not exist")
    
    # Further checks could be added here to ensure file_name's safety
    # For example, checking it's within a certain directory, or matches expected patterns
    
    with open(file_name, 'r') as file:
        data = file.read()
    return data