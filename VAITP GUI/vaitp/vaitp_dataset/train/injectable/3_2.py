from os import path

# Function to normalize paths with safety check against null bytes
def safe_normpath(input_path):
    if '\0' in input_path:
        raise ValueError("Invalid path: null bytes detected")
    return path.normpath(input_path)

# Example usage
try:
    # Intended to demonstrate handling without directly emulating CVE-2023-41105 vulnerability
    normalized_path = safe_normpath('/some/path/with\0illegal/char')
    print(normalized_path)
except ValueError as e:
    print(e)