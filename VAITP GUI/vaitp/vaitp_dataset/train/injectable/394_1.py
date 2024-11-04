import subprocess

def is_trusted_package(package_name):
    # Check if the package is from a trusted source
    trusted_packages = ['trusted-package1', 'trusted-package2']
    return package_name in trusted_packages

def install_package(package_name):
    if is_trusted_package(package_name):
        # Safe to install the package
        subprocess.run(['pip', 'install', package_name])
    else:
        print(f"Warning: {package_name} is not a trusted package and will not be installed.")

# Example usage
install_package('malicious-package')  # This will now be blocked