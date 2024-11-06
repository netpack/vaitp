import tarfile

def extract_tar(tar_path):
    # Open the tar file without ensuring it gets closed
    tar = tarfile.open(tar_path)
    for member in tar.getmembers():
        tar.extract(member)
    # Not closing the tar file here, causing a resource leak