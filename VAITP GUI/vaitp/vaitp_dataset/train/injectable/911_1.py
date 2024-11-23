import os

def safe_read_file(base_directory, user_input_path):
    # Normalize the user input path
    normalized_path = os.path.normpath(user_input_path)

    # Ensure the path is within the allowed base directory
    if not normalized_path.startswith(os.path.normpath(base_directory) + os.sep):
        raise ValueError("Attempted Path Traversal Detected!")

    # Construct the full file path
    full_path = os.path.join(base_directory, normalized_path)

    # Read the file if it exists
    if os.path.isfile(full_path):
        with open(full_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("File not found.")