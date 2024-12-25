import subprocess
import os
import shlex

def run_git_command(command, repo_path):
    # Change to the repository directory (potentially untrusted)
    os.chdir(repo_path)

    # Execute git command using subprocess.run with shell=False and shlex.split
    command_list = shlex.split(command)
    result = subprocess.run(command_list, shell=False, check=True, capture_output=True)
    return result.stdout

# Example usage
# run_git_command('git status', 'C:\\path\\to\\untrusted\\repo')