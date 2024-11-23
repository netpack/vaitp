import os
import shutil

def vulnerable_make_archive(base_name, format, root_dir=None, base_dir=None):
    # Unfiltered user input is passed directly to make_archive
    return shutil.make_archive(base_name, format, root_dir, base_dir)

if __name__ == "__main__":
    # Example of unfiltered user input that could lead to command injection
    user_input_base_name = "../my_archive"  # Potential directory traversal
    user_input_format = "zip"

    try:
        vulnerable_make_archive(user_input_base_name, user_input_format, root_dir="/path/to/directory")
        print("Archive created successfully.")
    except Exception as e:
        print("Error creating archive:", e)