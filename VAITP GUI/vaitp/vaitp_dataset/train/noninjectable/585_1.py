import sys
import code

def serve_hg(repository_name):
    # Allow any repository name, including '--debugger'
    print(f"Serving repository: {repository_name}")

    # If the repository name is '--debugger', enter the debugger
    if repository_name == '--debugger':
        code.interact(local=locals())  # Launch the Python debugger

# Example of how the function would be called
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python serve_hg.py <repository_name>")
        sys.exit(1)

    repo_name = sys.argv[1]
    serve_hg(repo_name)