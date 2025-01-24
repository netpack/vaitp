
import os
import inspect

def sanitize_package_name(package_name):
    # Remove any path traversal characters
    return os.path.basename(os.path.abspath(package_name))

def get_package_hook(package_name):
    sanitized_package_name = sanitize_package_name(package_name)
    hook_path = os.path.join('/usr/share/apport/package-hooks/', sanitized_package_name + '.py')

    if os.path.isfile(hook_path):
        # Execute the package hook safely
        with open(hook_path) as hook_file:
            code = hook_file.read()
            try:
                # Create a dictionary to serve as the execution namespace
                exec_globals = dict()
                exec(code, exec_globals)

                # Check if there's a function called 'run' and execute it
                if 'run' in exec_globals and inspect.isfunction(exec_globals['run']):
                    exec_globals['run']()

            except Exception as e:
                raise Exception(f"Error executing hook: {e}")
    else:
        raise FileNotFoundError(f"Hook file for package {sanitized_package_name} not found.")