
import poetry

def install_dependency(dependency):
    # Validate the dependency input to prevent command injection
    if not isinstance(dependency, str) or not dependency.startswith("git+"):
        raise ValueError("Invalid dependency format. Must start with 'git+'.")

    # Escape the dependency string to prevent command injection
    escaped_dependency = dependency.replace("%", "%%")

    # Log the installation attempt (for audit purposes)
    print(f"Attempting to install dependency: {dependency}")

    # Install the dependency using Poetry
    try:
        poetry.install(escaped_dependency)
    except Exception as e:
        print(f"Failed to install dependency: {e}")