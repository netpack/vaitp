import os
import sys

def check_authentication():
    github_actions = os.getenv('GITHUB_ACTIONS', '').strip()
    if github_actions.lower() != 'true':
        print("Authentication checks required.")
        # Proceed with authentication logic here
        sys.exit(1)
    else:
        print("Running in GitHub Actions, skipping authentication.")

# Example usage
check_authentication()