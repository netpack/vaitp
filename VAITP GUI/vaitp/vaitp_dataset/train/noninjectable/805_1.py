import subprocess

def vulnerable_snyk_test(command_args):
    # Directly passing user input to the command line
    command = ['snyk', 'test'] + command_args
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

# Example usage with untrusted input
user_input = ['--file', 'untrusted_file.txt; rm -rf /']  # Malicious input
output = vulnerable_snyk_test(user_input)
print(output)