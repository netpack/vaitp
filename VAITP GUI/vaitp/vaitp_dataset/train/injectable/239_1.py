import subprocess
import shlex

def run_gcov(file_path):
    # Validate the input to ensure it is a safe file path
    if not file_path.endswith('.c'):
        raise ValueError("Invalid file type. Only '.c' files are allowed.")
    
    # Use shlex to safely construct the command
    command = ['gcov', file_path]
    
    # Execute the command without shell=True to avoid command injection
    subprocess.Popen(command)

# Example of a safe input
safe_input = "file.c"
run_gcov(safe_input)