import subprocess
import shlex

def clone_repository(repo_url):
    # Using shlex.quote to properly escape the repo_url
    command = ["git", "clone", repo_url]
    subprocess.run(command, check=True)

# Example usage
clone_repository("https://example.com/repo.git")