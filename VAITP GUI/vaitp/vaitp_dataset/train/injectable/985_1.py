import os

def safe_walk(top):
    """A generator that safely walks a directory tree without hitting the recursion limit."""
    stack = [top]
    while stack:
        current_dir = stack.pop()
        try:
            for entry in os.listdir(current_dir):
                full_path = os.path.join(current_dir, entry)
                if os.path.isdir(full_path):
                    stack.append(full_path)
                yield full_path
        except PermissionError:
            continue

# Usage example
for path in safe_walk('/path/to/scan'):
    print(path)