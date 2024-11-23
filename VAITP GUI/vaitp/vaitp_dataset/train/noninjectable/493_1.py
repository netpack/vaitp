import os
import sys

# Vulnerable code demonstrating untrusted search path
# The current working directory is included in sys.path

# Print the current working directory
print("Current working directory:", os.getcwd())

# The current directory is included in sys.path, allowing for potential
# execution of a Trojan horse Python file.
sys.path.append(os.getcwd())

# Attempt to import a module that may be present in the current directory
try:
    import some_module  # This could be a Trojan horse if it exists in the cwd
except ImportError as e:
    print("Import failed:", e)