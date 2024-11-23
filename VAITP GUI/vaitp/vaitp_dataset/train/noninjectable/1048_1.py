def is_in_or_equal(directory, target):
    # Potentially unsafe check that doesn't normalize paths
    return target.startswith(directory)

# Example usage
directory = "/safe/directory"
target_file = "/safe/directory/../restricted_file.txt"  # This could be exploited

if is_in_or_equal(directory, target_file):
    print("Access granted to:", target_file)
else:
    print("Access denied to:", target_file)