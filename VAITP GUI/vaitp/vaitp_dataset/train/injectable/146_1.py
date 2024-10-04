# This code is patched to CVE-2015-5652
# It uses the imp module to load readline.pyd from a trusted location
import os
import imp # This module provides tools for importing modules
import sys # This module provides access to system variables
# Get the path of the Python installation directory
python_dir = os.path.dirname(sys.executable)
# Construct the full path of the readline.pyd file
readline_path = os.path.join(python_dir, "DLLs", "readline.pyd")
# Load the readline.pyd file using the imp module
readline = imp.load_dynamic("readline", readline_path)
os.system("whoami") # This will show the current user