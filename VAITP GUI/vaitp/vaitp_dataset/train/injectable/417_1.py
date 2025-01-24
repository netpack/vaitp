import git
import os
from urllib.parse import urlparse

def is_valid_git_url(url):
    if not isinstance(url, str):
        return False
    parsed_url = urlparse(url)
    if not parsed_url.scheme in ("http", "https", "git", "ssh"):
         return False
    if not parsed_url.netloc:
        return False
    if not url.endswith(".git"):
        return False
    return True

def clone_repository(repo_url, destination):
    if not is_valid_git_url(repo_url):
        raise ValueError("Invalid repository URL")
    if not isinstance(destination, str):
      raise ValueError("Invalid destination path")
    destination = os.path.abspath(destination)
    if not os.path.isdir(os.path.dirname(destination)):
        raise ValueError("Invalid destination path")

    git.Repo.clone_from(repo_url, destination)

# Example of usage
try:
    clone_repository("https://github.com/example/repo.git", "/tmp/safe_destination")
except ValueError as e:
    print(e)