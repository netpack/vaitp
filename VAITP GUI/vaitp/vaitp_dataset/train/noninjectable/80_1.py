import tarfile

# Create a malicious TAR archive
with open('malicious.tar', 'wb') as f:
    # Create a valid but empty tar archive by adding a null byte header
    f.write(b'\x00' * 512)

# Create a TAR file object
with tarfile.open('malicious.tar', 'r') as tar:
    # Iterate over the archive members
    for member in tar:
        print(member.name)