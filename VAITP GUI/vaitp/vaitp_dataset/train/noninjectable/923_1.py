import os

class Snippets:
    def __init__(self, base_path):
        self.base_path = os.path.abspath(base_path)

    def get_snippet_path(self, path):
        # Directly join the base path with the provided path
        full_path = os.path.join(self.base_path, path)
        
        # Return the full path without any validation
        return full_path