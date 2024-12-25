import tarfile

def extract_tar(tar_path):
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            tar.extract(member)