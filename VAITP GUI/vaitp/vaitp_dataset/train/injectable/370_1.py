# Hypothetical patched code
def save_content(data, filename, user):
    # Check if the user has permission to write to the specified file
    if not user.has_permission('write', filename):
        raise PermissionError("You do not have permission to write to this file.")
    
    with open(filename, 'w') as file:
        file.write(data)