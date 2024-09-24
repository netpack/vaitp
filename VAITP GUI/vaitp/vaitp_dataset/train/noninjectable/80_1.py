import tarfile

# Create a malicious TAR archive
with open('malicious.tar', 'wb') as f:
    f.write(b'')  # Empty TAR archive

# Create a TAR file object
with tarfile.open('malicious.tar', 'r') as tar:
    # Iterate over the archive members
    for member in tar:
        print(member.name)  # This will cause an infinite loop