import subprocess

def vulnerable_exec(command, metadata):
    # Directly format the command with unvalidated metadata
    command_to_run = command.format(**metadata)

    # Execute the command without proper escaping
    subprocess.run(command_to_run, shell=True)

# Example usage
metadata = {
    'filepath': 'example.mp4',
    'title': 'example title with & special chars',
}

# This command is vulnerable to injection
command = 'echo {title} > {filepath}'

vulnerable_exec(command, metadata)