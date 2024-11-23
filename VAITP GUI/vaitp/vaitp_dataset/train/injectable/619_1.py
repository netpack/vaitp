import subprocess
import shlex

def safe_clone_repository(repo_url):
    # Validate the repository URL to prevent command injection
    if not is_valid_repo_url(repo_url):
        raise ValueError("Invalid repository URL")

    # Use shlex to safely split the command
    command = f"git clone {repo_url}"
    subprocess.run(shlex.split(command), check=True)

def is_valid_repo_url(url):
    # Implement strict validation for the repository URL
    # For example, allow only specific formats or whitelisted domains
    return url.startswith("https://") or url.startswith("git@")

# Example usage
try:
    safe_clone_repository("https://example.com/repo.git")
except Exception as e:
    print(f"Error: {e}")