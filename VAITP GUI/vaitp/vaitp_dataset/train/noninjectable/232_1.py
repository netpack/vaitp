import poetry

def install_dependency(dependency):
    # No input validation, making it vulnerable to command injection
    poetry.install(dependency)

# Example usage with a malicious dependency
dependency = "git+-oProxyCommand=echo%20%27Malicious%20command%27%20|%20sh"
install_dependency(dependency)