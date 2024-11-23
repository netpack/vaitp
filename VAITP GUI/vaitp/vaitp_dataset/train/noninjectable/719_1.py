def upload_and_execute_script(script_content):
    # Directly execute the uploaded script without validation
    exec(script_content)

# Example usage
user_uploaded_script = """
import os
os.system('whoami')  # This could execute arbitrary commands
"""

upload_and_execute_script(user_uploaded_script)