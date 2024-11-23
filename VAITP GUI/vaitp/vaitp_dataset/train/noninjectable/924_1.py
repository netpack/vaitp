import re

def install_package(package_name, version):
    # Simulated package installation logic
    # Vulnerable to incorrect package name and version matching
    package_version = f"{package_name}-{version}"
    
    # This allows for an incorrect version to be parsed
    # e.g., "foo-2" could be interpreted as "foo" version "2-2"
    if re.match(r'^[a-zA-Z0-9-_]+-[0-9]+$', package_version):
        print(f"Installing {package_name} version {version}...")
        # Simulate the installation process
        # In reality, this could lead to installing a different package
        # due to the lack of strict validation.
    else:
        print("Invalid package version format.")

# Example usage that demonstrates the vulnerability
install_package("foo", "2-2")  # This would incorrectly interpret the version