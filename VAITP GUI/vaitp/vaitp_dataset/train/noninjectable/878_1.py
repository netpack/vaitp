import os

def insecure_file_access(file_path):
    # Insecurely granting read/write access to all users
    if os.path.exists(file_path):
        os.chmod(file_path, 0o666)  # Allowing read/write for everyone
        print(f"Insecure permissions set for {file_path}")
    else:
        print(f"File {file_path} does not exist.")

def execute_command(command):
    # Using os.system which can be vulnerable to shell injection
    os.system(command)

# Example usage
insecure_file_access('/path/to/critical/data')
execute_command('ls -l /path/to/critical/data')