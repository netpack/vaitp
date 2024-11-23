import urllib.parse
import os

def execute_script(encoded_script_path):
    # Directly decode the URL-encoded script path without validation
    script_path = urllib.parse.unquote(encoded_script_path)

    # Vulnerable: No normalization or safety checks on the script path
    exec(open(script_path).read())

# Example usage (make sure to replace with actual script path)
# execute_script("path/to/your/script.py")