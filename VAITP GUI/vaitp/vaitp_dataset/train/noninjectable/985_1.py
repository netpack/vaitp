import os

def vulnerable_walk(top):
    """A function that demonstrates the vulnerability by using os.walk(), which can hit recursion limits."""
    for dirpath, dirnames, filenames in os.walk(top):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            print(full_path)

# Usage example
vulnerable_walk('/path/to/scan')