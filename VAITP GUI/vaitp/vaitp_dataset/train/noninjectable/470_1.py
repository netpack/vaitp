import sys

def handle_core_dump(module_name):
    # Vulnerable code that imports a module based on user input
    try:
        # Import a module dynamically based on user input
        __import__(module_name)
    except ImportError as e:
        print(f"Error importing module: {e}")

# Simulating a core dump handling where user input is not sanitized
user_input = sys.argv[1]  # Assume this comes from user input
handle_core_dump(user_input)