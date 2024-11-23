def install_package(git_url, reference):
    # Vulnerable code: does not sanitize the reference
    # This could allow an attacker to inject a Unicode separator
    print(f"Installing package from {git_url} at reference {reference}")

# Example usage
install_package("https://github.com/example/repo.git", "main\u2028branch")