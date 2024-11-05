import tarfile

def extract_package(package_path, extract_to):
    with tarfile.open(package_path, 'r:gz') as tar:
        tar.extractall(path=extract_to)

# Example usage
extract_package('malicious_package.tar.gz', '/safe/directory/')