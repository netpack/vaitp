import subprocess

def upload_and_execute_script(script_content):
    # Instead of directly executing the script with 'exec', which is highly dangerous,
    # this example demonstrates a safer approach using subprocess.

    # This is still not fully secure (e.g., if you are handling arbitrary inputs
    # from untrusted sources), and we are just illustrating a potential correction.
    # In a production setting, the best approach depends heavily on the use case,
    # and you should never execute untrusted code.

    # Create a temporary file to store the script.
    try:
        with open("temp_script.py", "w") as f:
            f.write(script_content)
        
        # Use subprocess to execute the script in a controlled environment.
        process = subprocess.Popen(["python", "temp_script.py"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print("Script executed successfully:")
            print(stdout.decode())
        else:
            print("Script execution failed:")
            print(stderr.decode())
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
      import os
      # Clean up the temporary file
      if os.path.exists("temp_script.py"):
        os.remove("temp_script.py")

# Example usage
user_uploaded_script = """
import os
print(os.system('whoami'))  # This could execute arbitrary commands, but here we print its output
"""

upload_and_execute_script(user_uploaded_script)