import os
import subprocess

def secure_file_access(file_path):
    # Ensure that the file permissions are set securely
    if os.path.exists(file_path):
        os.chmod(file_path, 0o600)  # Only owner can read/write
        print(f"Secure permissions set for {file_path}")
    else:
        print(f"File {file_path} does not exist.")

def execute_command(command):
    # Use subprocess with a list to avoid shell injection vulnerabilities
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Command executed successfully:", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error executing command:", e.stderr)

# Example usage
secure_file_access('/path/to/critical/data')
execute_command(['ls', '-l', '/path/to/critical/data'])