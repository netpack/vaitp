import tarfile

# Create a TAR file object with a custom error handler
def _error_handler(tar, func, path):
    raise RuntimeError("Error processing TAR archive")

with tarfile.open('malicious.tar', 'r', error_handler=_error_handler) as tar:
    # Iterate over the archive members
    for member in tar:
        print(member.name)