import os
import sys
from urllib.parse import quote

local_dir = "/tmp"  # Or any safe directory
if len(sys.argv) > 1:
    path = sys.argv[1]
    f_name = os.path.basename(path)
    file = os.path.join(local_dir, f_name)
else:
    print("No path provided")
    sys.exit(1)