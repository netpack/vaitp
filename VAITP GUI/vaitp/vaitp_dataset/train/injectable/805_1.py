import subprocess

def safe_snyk_test(command_args):
    # Validate command_args to prevent command injection
    # Here, we only allow specific, safe arguments
    allowed_args = ['--all-projects', '--json', '--file', '--path']
    for arg in command_args:
        if arg not in allowed_args:
            raise ValueError(f"Unsafe argument detected: {arg}")
    
    # Execute the Snyk test command safely
    command = ['snyk', 'test'] + command_args
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

# Example usage
try:
    output = safe_snyk_test(['--all-projects'])
    print(output)
except ValueError as e:
    print