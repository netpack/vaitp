import tarfile

# Create a tarfile object
tar = tarfile.TarFile('example.tar', 'w')

# Add a file to the tarfile with a path that could trigger the vulnerability
tar.add('../etc/passwd')