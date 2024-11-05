import shutil
import os

def is_safe_path(base, path):
    # Resolve the absolute paths
    base = os.path.abspath(base)
    path = os.path.abspath(path)
    # Check if the resolved path starts with the base path
    return os.path.commonpath([base]) == os.path.commonpath([base, path])

def extract_package(package_path, target_directory):
    # Create the target directory if it doesn't exist
    os.makedirs(target_directory, exist_ok=True)

    # Extract the archive
    temp_extract_path = os.path.join(target_directory, 'temp_extracted')
    shutil.unpack_archive(package_path, temp_extract_path)

    # Validate extracted files
    for root, dirs, files in os.walk(temp_extract_path):
        for name in files:
            file_path = os.path.join(root, name)
            if not is_safe_path(target_directory, file_path):
                print(f"Unsafe file detected: {file_path}")
                # Handle the unsafe file (e.g., remove it, raise an exception, etc.)

    # Move files from temp_extract_path to target_directory
    for root, dirs, files in os.walk(temp_extract_path):
        for name in files:
            shutil.move(os.path.join(root, name), target_directory)
    
    # Clean up temporary extraction directory
    shutil.rmtree(temp_extract_path)

# Example usage
extract_package('malicious_package.zip', '/path/to/target/directory')