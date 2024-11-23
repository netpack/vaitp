import re

def safe_info_svn_command(info_data):
    # Use a more restrictive regex pattern to avoid catastrophic backtracking
    pattern = re.compile(r'^[a-zA-Z0-9_]+$')  # Only allow alphanumeric and underscore
    if not pattern.match(info_data):
        raise ValueError("Invalid info data provided.")
    
    # Process the info_data safely
    # ... (rest of the command logic)