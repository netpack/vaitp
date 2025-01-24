from werkzeug.utils import safe_join
import os

# Example of a potentially unsafe path
base_path = "C:\\myapp"
unsafe_path = "//server/share"

# To fix the vulnerability, ensure you are using Werkzeug 3.0.6 or later.
# Additionally, you can manually check for UNC paths before calling safe_join
if unsafe_path.startswith("//") or os.path.isabs(unsafe_path):
    print("Unsafe path detected, not joining.")
else:
    safe_path = safe_join(base_path, unsafe_path)
    print("Safe path:", safe_path)