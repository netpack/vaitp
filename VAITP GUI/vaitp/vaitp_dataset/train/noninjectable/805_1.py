import subprocess
import shlex

def vulnerable_snyk_test(command_args):
    # Properly escape or sanitize user input to prevent command injection
    command = ['snyk', 'test'] + [shlex.quote(arg) for arg in command_args]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

# Example usage with untrusted input
user_input = ['--file', 'untrusted_file.txt; rm -rf /']  # Malicious input
output = vulnerable_snyk_test(user_input)
print(output)