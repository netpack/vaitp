import sys

# List of allowed modules
ALLOWED_MODULES = {'module1', 'module2', 'module3'}

def handle_core_dump(module_name):
    # Check if the requested module is in the allowed list
    if module_name in ALLOWED_MODULES:
        try:
            __import__(module_name)
        except ImportError as e:
            print(f"Error importing module: {e}")
    else:
        print(f"Attempt to import disallowed module: {module_name}")

# Simulating a core dump handling where user input is checked
user_input = sys.argv[1]  # Assume this comes from user input
handle_core_dump(user_input)