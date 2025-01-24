
import os
import sys
import urllib.parse

if len(sys.argv) > 1:
    f_name = sys.argv[1]

    if not f_name or not isinstance(f_name, str):
        print("Invalid filename")
        sys.exit(1)

    f_path = f_name
    if os.path.sep in f_name:
        f_path = os.path.basename(f_name)
    if not os.path.exists(f_path) or not os.path.isfile(f_path):
        print("Invalid filename")
        sys.exit(1)

    # Validate filename against path traversal attempts
    f_path = urllib.parse.unquote(f_path)
    if not f_path.startswith('.') and not os.path.abspath(f_path).startswith(os.path.abspath(os.getcwd())):
        print("Invalid filename")
        sys.exit(1)

    try:
        with open(f_path, 'r') as f:
            exec(f.read(), {}, {})
    except Exception as e:
        print(f"Error executing file: {e}")