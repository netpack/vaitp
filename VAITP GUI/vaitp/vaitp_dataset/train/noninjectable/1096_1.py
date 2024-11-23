from werkzeug.utils import safe_join

# Example of a potentially unsafe path
base_path = "C:\\myapp"
unsafe_path = "//server/share"

# This demonstrates the vulnerability in versions of Werkzeug prior to the fix
safe_path = safe_join(base_path, unsafe_path)
print("Safe path:", safe_path)  # This may produce an unsafe path