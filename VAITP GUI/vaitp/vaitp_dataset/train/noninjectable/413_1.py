import shutil

def extract_package(package_path, target_directory):
    # This is the vulnerable code
    shutil.unpack_archive(package_path, target_directory)

# Example usage
extract_package('malicious_package.zip', '/path/to/target/directory')