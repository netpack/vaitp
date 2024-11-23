import json
import os
from processing_utils import move_files_to_cache

def postprocess(user_input):
    # Parse user-controlled input as JSON
    parsed_json = json.loads(user_input)
    
    # If the parsed JSON object contains a 'path' key, move the specified file
    if isinstance(parsed_json, dict) and 'path' in parsed_json:
        file_path = parsed_json['path']
        move_files_to_cache(file_path)  # Vulnerable to local file inclusion

# Example usage
user_input = '{"path": "/etc/passwd"}'  # Example of malicious input
postprocess(user_input)