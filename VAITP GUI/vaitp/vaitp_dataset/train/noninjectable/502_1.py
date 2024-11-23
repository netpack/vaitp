import os
import sys

# Example of vulnerable code that allows untrusted imports
if __name__ == "__main__":
    # Directly using the current working directory in sys.path
    sys.path.insert(0, os.getcwd())

    # Import a module that could potentially be a Trojan horse
    import untrusted_module