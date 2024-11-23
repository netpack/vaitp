import os

class SecureActiveXControl:
    def __init__(self):
        self.allowed_paths = [os.path.expanduser("~")]  # Limit access to the user's home directory

    def read_file(self, file_path):
        # Normalize the path to prevent directory traversal
        normalized_path = os.path.abspath(file_path)
        
        # Check if the normalized path is within the allowed paths
        if any(normalized_path.startswith(os.path.abspath(allowed_path)) for allowed_path in self.allowed_paths):
            with open(normalized_path, 'r') as file:
                return file.read()
        else:
            raise PermissionError("Access to the requested file is denied.")

# Example usage
secure_control = SecureActiveXControl()
try:
    content = secure_control.read_file("example.txt")  # Only allows reading files in the user's home directory
    print(content)
except PermissionError as e:
    print(e)