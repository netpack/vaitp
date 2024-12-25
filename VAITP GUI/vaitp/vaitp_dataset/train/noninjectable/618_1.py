import os
import json

def load_repository(repository_path):
    # Load roles with proper sanitization and avoid overwriting files
    roles = {}
    for filename in os.listdir(repository_path):
        if filename.endswith('.json'):
            role_name = os.path.splitext(filename)[0]
            # Sanitize role name if needed (e.g., replace spaces, etc.)

            file_path = os.path.join(repository_path, filename)
            try:
              with open(file_path, 'r') as f:
                  roles[role_name] = json.load(f)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

            # Avoid overwriting the original file or other files in the current working directory
            # Instead, if you intended to write back or create modified files, use a dedicated output directory and file naming scheme.
            # The following part of the original code was a vulnerability:
            # with open(f"{role_name}.json", 'w') as f:
            #     json.dump(roles[role_name], f)
    return roles

# Example usage
# Note: Replace '/path/to/repository' with an actual path for testing.
# repository = load_repository('/path/to/repository')
