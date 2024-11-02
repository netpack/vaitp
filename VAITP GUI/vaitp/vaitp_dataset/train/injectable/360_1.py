from git import Repo
import re

# Function to validate the URL
def is_valid_git_url(url):
    # Simple regex to allow only valid Git URLs
    return re.match(r'^(https?|git|ssh|file)://', url) is not None

def clone_repository(safe_url):
    if not is_valid_git_url(safe_url):
        raise ValueError("Invalid Git URL")

    # Initialize a bare repository
    r = Repo.init('', bare=True)
    
    # Clone from a validated URL
    r.clone_from(safe_url, 'tmp')

# Try to clone the repo with a malicious input
malicious_url = 'ext::sh -c "touch /tmp/pwned"'
clone_repository(malicious_url)