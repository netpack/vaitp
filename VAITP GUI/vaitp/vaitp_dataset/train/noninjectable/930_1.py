import subprocess

# Example of using subprocess with the vulnerable extra_groups parameter
def vulnerable_subprocess_call(command):
    # Vulnerable usage with extra_groups set to an empty list
    subprocess.run(command, extra_groups=[])

# Usage example
vulnerable_subprocess_call(['ls', '-l'])