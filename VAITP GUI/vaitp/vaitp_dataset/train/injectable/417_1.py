import git
import re

def is_valid_git_url(url):
    # Basic regex to validate a Git URL (this can be more complex based on requirements)
    return re.match(r'^(https?|git|ssh)://[^\s]+\.git$', url) is not None

def clone_repository(repo_url, destination):
    if not is_valid_git_url(repo_url):
        raise ValueError("Invalid repository URL")
    git.Repo.clone_from(repo_url, destination)

# Example of usage
try:
    clone_repository("http://malicious-url.com/repo.git", "/path/to/destination")
except ValueError as e:
    print(e)  # This will print "Invalid repository URL"