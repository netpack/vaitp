import os
import shutil

def secure_make_archive(base_name, format, root_dir=None, base_dir=None):
    # Validate base_name to prevent directory traversal or command injection
    if os.path.basename(base_name) != base_name:
        raise ValueError("Invalid base_name: directory traversal detected.")
    
    # Ensure that the format is one of the allowed types
    allowed_formats = ['zip', 'tar', 'gztar', 'bztar', 'xztar']
    if format not in allowed_formats:
        raise ValueError(f"Invalid format: {format}. Allowed formats are: {allowed_formats}")

    # Call the original make_archive function with validated parameters
    return shutil.make_archive(base_name, format, root_dir, base_dir)

if __name__ == "__main__":
    try:
        secure_make_archive("my_archive", "zip", root_dir="/path/to/directory")
        print("Archive created successfully.")
    except Exception as e:
        print("Error creating archive:", e)