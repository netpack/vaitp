import subprocess

# Example of a secure package installation process to prevent dependency confusion
def secure_install(package_name):
    try:
        # Check if the package is available in the private repository first
        subprocess.run(["pip", "install", "--no-index", "--find-links=https://my-private-repo.com/packages", package_name], check=True)
    except subprocess.CalledProcessError:
        # If it fails, fall back to the public repository
        print(f"Installing {package_name} from public repository")
        subprocess.run(["pip", "install", package_name], check=True)

# Example usage
secure_install("my-package")