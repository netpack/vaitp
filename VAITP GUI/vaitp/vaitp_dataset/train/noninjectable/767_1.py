```
```python
import os

def get_package_hook(package_name):
    hook_path = os.path.join('/usr/share/apport/package-hooks/', package_name + '.py')

    if os.path.isfile(hook_path):
        # Execute the package hook without sanitization
        try:
          with open(hook_path) as hook_file:
              exec(hook_file.read())
        except Exception as e:
          print(f"Error executing hook for {package_name}: {e}")
    else:
        raise FileNotFoundError(f"Hook file for package {package_name} not found.")