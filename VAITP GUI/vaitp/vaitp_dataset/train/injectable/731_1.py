import urllib.parse
import os

def is_safe_script_path(script_path):
    # Normalize the path to prevent directory traversal
    normalized_path = os.path.normpath(script_path)
    # Ensure the path is within the allowed directories
    allowed_dirs = ["/path/to/share/Scripts/python", "/path/to/user/Scripts/python"]
    return any(normalized_path.startswith(os.path.normpath(allowed_dir)) for allowed_dir in allowed_dirs)

def execute_script(encoded_script_path):
    # Decode the URL-encoded script path
    script_path = urllib.parse.unquote(encoded_script_path)
    
    if is_safe_script_path(script_path):
        # Execute the script if it's safe
        try:
            with open(script_path, 'r') as f:
                exec(f.read())
        except FileNotFoundError:
            raise ValueError(f"Script file not found at path: {script_path}")
        except Exception as e:
            raise ValueError(f"Error executing script: {e}")
    else:
        raise ValueError("Attempted to execute a script outside of allowed directories.")

# Example usage (make sure to replace with actual script path)
# execute_script("path/to/your/script.py")