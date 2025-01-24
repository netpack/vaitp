
import os
import sys
import re
from urllib.parse import quote_plus

if len(sys.argv) < 5:
    print("Usage: script.py ... <input>")
    sys.exit(1)

inputvar = sys.argv[4]

if not isinstance(inputvar, str):
    print("Input must be a string.")
    sys.exit(1)

if not re.match(r'^[a-zA-Z0-9._-]+$', inputvar):
    print("Input contains invalid characters.")
    sys.exit(1)

inputvar = quote_plus(inputvar)  # Escape special characters to prevent path traversal attacks
local_dir = "./"
extensive_path = os.path.join(local_dir, inputvar)