import subprocess
import os

def run_git_command(command, repo_path):
    # Change to the repository directory (potentially untrusted)
    os.chdir(repo_path)

    # Execute git command using the shell
    result = subprocess.run(command, shell=True, check=True, capture_output=True)
    return result.stdout

# Example usage
# run_git_command('git status', 'C:\\path\\to\\untrusted\\repo')