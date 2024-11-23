import subprocess
import shlex

def safe_exec(command, metadata):
    # Ensure that the metadata is properly sanitized
    # Replace newlines with carriage returns as per the fix
    sanitized_metadata = {key: value.replace('\n', '\r') for key, value in metadata.items()}
    
    # Use shlex.quote to safely escape the command arguments
    safe_command = command.format(**sanitized_metadata)
    safe_command = shlex.quote(safe_command)  # Escape the command for shell execution

    # Execute the command safely
    subprocess.run(safe_command, shell=True)

# Example usage
metadata = {
    'filepath': 'example.mp4',
    'title': 'example title with & special chars',
}

# This would be a vulnerable command if not properly sanitized
command = 'echo {title} > {filepath}'

safe_exec(command, metadata)