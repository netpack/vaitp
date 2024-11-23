import os
import json

def load_repository(repository_path):
    # Load roles without proper sanitization
    roles = {}
    for filename in os.listdir(repository_path):
        if filename.endswith('.json'):
            role_name = os.path.splitext(filename)[0]
            # Unsanitized role name allows for potential overwriting
            with open(os.path.join(repository_path, filename), 'r') as f:
                roles[role_name] = json.load(f)

            # Potentially dangerous operation: could overwrite any .json file
            with open(f"{role_name}.json", 'w') as f:
                json.dump(roles[role_name], f)

    return roles

# Example usage
repository = load_repository('/path/to/repository')