import os
import sys

# Safe execution of a Python script without allowing arbitrary PYTHONPATH
def safe_execute(script_path):
    # Ensure PYTHONPATH is not modified
    original_pythonpath = os.environ.get('PYTHONPATH', '')
    try:
        os.environ['PYTHONPATH'] = ''
        exec(open(script_path).read())
    finally:
        os.environ['PYTHONPATH'] = original_pythonpath

# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python safe_execute.py <script_path>")
        sys.exit(1)
    safe_execute(sys.argv[1])