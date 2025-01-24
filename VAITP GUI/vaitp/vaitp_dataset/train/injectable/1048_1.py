import os

def is_in_or_equal(directory, target):
    # Normalize the paths
    directory = os.path.abspath(directory)
    target = os.path.abspath(target)

    # Check if the target is within the directory, ensuring no path traversal
    return target.startswith(directory) and os.path.commonpath([directory, target]) == directory

# Example usage
directory = "/safe/directory"
target_file = "/safe/directory/../restricted_file.txt"  # This should be blocked

if is_in_or_equal(directory, target_file):
    print("Access granted to:", target_file)
else:
    print("Access denied to:", target_file)
