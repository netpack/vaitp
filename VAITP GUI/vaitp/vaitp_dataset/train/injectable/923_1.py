import os

class Snippets:
    def __init__(self, base_path):
        self.base_path = os.path.abspath(base_path)

    def get_snippet_path(self, path):
        # Normalize the path to prevent directory traversal
        normalized_path = os.path.normpath(path)
        
        # Check if the normalized path starts with the base path
        if not normalized_path.startswith(self.base_path):
            raise ValueError("Access to the specified path is not allowed.")
        
        # Join the base path with the normalized path
        full_path = os.path.join(self.base_path, normalized_path)
        
        # Check if the resulting path is within the allowed base path
        if not os.path.isfile(full_path):
            raise FileNotFoundError("The specified file does not exist.")
        
        return full_path