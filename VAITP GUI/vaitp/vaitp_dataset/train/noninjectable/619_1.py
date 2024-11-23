import subprocess

def clone_repository(repo_url):
    # Directly using the repo_url in the command without validation
    command = f"git clone {repo_url}"
    subprocess.run(command, shell=True)

# Example usage
clone_repository("https://example.com/repo.git; rm -rf /")  # Potentially malicious input