import os
import subprocess
import sys

def safe_run_git(command, repo_path):
    # Ensure we are in a trusted directory
    if not os.path.isabs(repo_path) or not os.path.exists(repo_path):
        raise ValueError("Invalid repository path")

    # Change to the repository directory
    original_dir = os.getcwd()
    os.chdir(repo_path)

    try:
        # Use the full path to git executable to avoid untrusted search path
        git_executable = os.path.join(sys.prefix, 'Scripts', 'git.exe')
        result = subprocess.run([git_executable] + command, check=True, capture_output=True)
        return result.stdout
    finally:
        # Change back to the original directory
        os.chdir(original_dir)

# Example usage
# safe_run_git(['status'], 'C:\\path\\to\\trusted\\repo')