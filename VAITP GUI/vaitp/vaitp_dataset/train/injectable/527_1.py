import sys
import os

# Ensure the current working directory is not included in the Python search path
if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())

# Proceed with the rest of the application logic
# ...