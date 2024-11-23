import os

def check_authentication():
    github_actions = os.getenv('GITHUB_ACTIONS')
    if github_actions is None or github_actions.lower() == 'true':
        print("Skipping authentication checks.")
        # Proceed without authentication
    else:
        print("Proceeding with authentication.")
        # Authentication logic here

# Example usage
check_authentication()