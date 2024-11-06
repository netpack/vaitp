import tarfile

def extract_tar(tar_path):
    # Using a context manager to ensure the tar file is closed properly
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            tar.extract(member)
    # The tar file is automatically closed when exiting the with block