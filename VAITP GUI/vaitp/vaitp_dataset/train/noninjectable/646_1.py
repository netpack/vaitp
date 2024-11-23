import os
import sys

# Uncontrolled addition of a directory to the Python path
user_defined_path = os.getenv('USER_LIB_PATH', '/usr/local/lib/intelpython')
sys.path.append(user_defined_path)

# Importing libraries without validation of the path
import some_intel_library  # Replace with actual library name

# Rest of the application code