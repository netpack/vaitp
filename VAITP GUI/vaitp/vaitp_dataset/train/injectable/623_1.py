import os
import subprocess

# Function to safely load scripts without executing arbitrary code
def safe_load_gdb_script(script_name):
    # Define a safe directory for loading scripts
    safe_directory = "/path/to/safe/directory"
    
    # Ensure the script is within the safe directory
    if os.path.abspath(script_name).startswith(os.path.abspath(safe_directory)):
        subprocess.run(["gdb", "-x", script_name])
    else:
        print("Error: Attempt to load script from an unsafe directory.")

# Example usage
safe_load_gdb_script("example_script.py")