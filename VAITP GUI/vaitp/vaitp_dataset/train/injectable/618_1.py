import os
import json

def safe_load_repository(repository_path):
    # Ensure the repository path is valid and does not contain malicious role names
    if not os.path.isdir(repository_path):
        raise ValueError("Invalid repository path")

    # Load roles safely
    roles = {}
    for filename in os.listdir(repository_path):
        if filename.endswith('.json'):
            role_name = os.path.splitext(filename)[0]
            # Sanitize role name to prevent directory traversal or overwriting
            if not is_safe_role_name(role_name):
                raise ValueError(f"Unsafe role name detected: {role_name}")

            with open(os.path.join(repository_path, filename), 'r') as f:
                roles[role_name] = json.load(f)

    return roles

def is_safe_role_name(role_name):
    # Implement sanitization logic, e.g., disallow certain characters or patterns
    return all(c.isalnum() or c in ('-', '_') for c in role_name)

# Example usage
try:
    repository = safe_load_repository('/path/to/repository')
except ValueError as e:
    print(f"Error loading repository: {e}")