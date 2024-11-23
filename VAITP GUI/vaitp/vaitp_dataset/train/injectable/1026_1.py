import urllib.parse
from notebook.utils import url_path_join

def safe_folder_name(folder_name):
    # Escape the folder name to prevent XSS
    return urllib.parse.quote(folder_name)

def create_folder(folder_name):
    safe_name = safe_folder_name(folder_name)
    folder_path = url_path_join('/path/to/folders', safe_name)
    # Logic to create the folder using folder_path
    # ...

# Example usage
create_folder("<script>alert('XSS');</script>")