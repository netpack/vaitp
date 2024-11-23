import os

def sanitize_package_name(package_name):
    # Remove any path traversal characters
    return os.path.basename(package_name)

def get_package_hook(package_name):
    sanitized_package_name = sanitize_package_name(package_name)
    hook_path = os.path.join('/usr/share/apport/package-hooks/', sanitized_package_name + '.py')

    if os.path.isfile(hook_path):
        # Execute the package hook safely
        with open(hook_path) as hook_file:
            exec(hook_file.read())
    else:
        raise FileNotFoundError(f"Hook file for package {sanitized_package_name} not found.")