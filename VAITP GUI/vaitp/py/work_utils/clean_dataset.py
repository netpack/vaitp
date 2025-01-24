import os
import ast

def is_valid_python_code(filepath):
    """
    Checks if the content of a file is valid Python code.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: True if the file contains valid Python code, False otherwise.
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        ast.parse(content)
        return True
    except (SyntaxError, TypeError, UnicodeDecodeError):
        return False

def clean_dataset_directory(dataset_dir):
    """
    Loops through all files in the dataset directory and deletes those
    that do not contain valid Python code.

    Args:
        dataset_dir (str): The path to the dataset directory.
    """
    deleted_count = 0
    checked_count = 0
    for filename in os.listdir(dataset_dir):
        filepath = os.path.join(dataset_dir, filename)
        if os.path.isfile(filepath) and filename.endswith(".py"):
            checked_count += 1
            if not is_valid_python_code(filepath):
                try:
                    os.remove(filepath)
                    deleted_count += 1
                    print(f"Deleted non-Python file: {filename}")
                except OSError as e:
                    print(f"Error deleting file {filename}: {e}")

    print(f"\nChecked {checked_count} files with '.py' extension.")
    print(f"Deleted {deleted_count} files that did not contain valid Python code.")

if __name__ == "__main__":
    dataset_directory = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/noninjectable/"
    clean_dataset_directory(dataset_directory)