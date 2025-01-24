
import re
import subprocess
import shlex

def sanitize_git_reference(reference):
    # Remove any characters that are not alphanumeric, underscore, or hyphen
    sanitized_reference = re.sub(r'[^\w\-]+', '', reference)
    
    # Check if the sanitized reference is only made up of ASCII characters
    if not all(ord(char) < 128 for char in sanitized_reference):
        raise ValueError("Sanitized reference contains non-ASCII characters")
    
    return sanitized_reference

def install_package(git_url, reference):
    sanitized_reference = sanitize_git_reference(reference)
    command = shlex.split(f"git clone --depth 1 -b {sanitized_reference} {git_url} package")
    try:
        subprocess.run(command, check=True, capture_output=True)
        print(f"Installed package from {git_url} at reference {sanitized_reference}")
    except subprocess.CalledProcessError as e:
        print(f"Error installing package: {e}")
        print(f"Error output: {e.stderr.decode()}")


# Example usage
install_package("https://github.com/example/repo.git", "main")