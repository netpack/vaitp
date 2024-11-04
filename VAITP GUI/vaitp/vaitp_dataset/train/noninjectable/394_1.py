import subprocess

def install_package(package_name):
    # Vulnerable code: directly installing a package without validation
    subprocess.run(['pip', 'install', package_name])

# Example usage
install_package('malicious-package')  # This could be a crafted package