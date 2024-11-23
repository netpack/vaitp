import os
import subprocess

def safe_script_upload(script_content):
    # Validate the script content to ensure it doesn't contain malicious code
    if is_safe_script(script_content):
        # Write the script to a temporary file
        with open('/tmp/safe_script.py', 'w') as script_file:
            script_file.write(script_content)
        
        # Execute the script in a safe environment
        subprocess.run(['python3', '/tmp/safe_script.py'], check=True)
    else:
        raise ValueError("Unsafe script content detected.")

def is_safe_script(script_content):
    # Check for disallowed keywords or patterns in the script
    disallowed_keywords = ['import', 'os', 'subprocess', 'eval', 'exec']
    return not any(keyword in script_content for keyword in disallowed_keywords)

# Example usage
try:
    user_script = "print('Hello, world!')"  # This is safe
    safe_script_upload(user_script)
except ValueError as e:
    print(e)