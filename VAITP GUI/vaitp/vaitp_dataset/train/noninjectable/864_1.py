import os
import pathlib

def execute_librelogo_script(script_name):
    # This function simulates executing a LibreLogo script with path traversal protection
    
    base_dir = pathlib.Path("C:\\Program Files\\LibreOffice\\share\\librelogo")
    script_path = base_dir / f"{script_name}.py"

    # Resolve the path and ensure it's within the allowed base directory
    script_path = script_path.resolve()

    if not script_path.is_relative_to(base_dir):
        print("Error: Script path is outside the allowed directory.")
        return
    
    if not script_path.exists():
      print(f"Error: Script not found at {script_path}")
      return

    # Execute the script directly
    try:
      with open(script_path, 'r') as f:
          exec(f.read())
    except Exception as e:
        print(f"Error executing script: {e}")

# Example of a potentially malicious filename
malicious_script = "..\\..\\..\\..\\..\\..\\Windows\\System32\\malicious_script" #Removed C:\\Program Files\\LibreOffice\\share\\librelogo\\ from the path

# Execute the script, which could lead to arbitrary code execution
execute_librelogo_script(malicious_script)

#Example of a valid file
valid_script = "test"
execute_librelogo_script(valid_script)