import subprocess

# Example of a vulnerable package installation process
def vulnerable_install(package_name):
    # This command installs the package without checking its source
    subprocess.run(["pip", "install", package_name], check=True)

# Example usage
vulnerable_install("malicious-package")