import os
import sys

def serve_hg(repository_name):
    # Prevent the use of '--debugger' as a repository name
    if repository_name == '--debugger':
        raise ValueError("Invalid repository name: '--debugger' is not allowed.")

    # Proceed with serving the repository
    print(f"Serving repository: {repository_name}")
    # Additional code to serve the repository...

# Example of how the function would be called
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python serve_hg.py <repository_name>")
        sys.exit(1)

    repo_name = sys.argv[1]
    serve_hg(repo_name)