import os
import subprocess

# Example of using subprocess with extra_groups parameter safely
def safe_subprocess_call(command, extra_groups=None):
    # Ensure extra_groups is not an empty list to avoid the vulnerability
    if extra_groups is None or len(extra_groups) > 0:
        # Drop original groups before executing the command
        os.setgroups(0, [])
        # Call the subprocess with the specified groups
        subprocess.run(command, extra_groups=extra_groups)

# Usage example
safe_subprocess_call(['ls', '-l'], extra_groups=[1001, 1002])