# Import the tarfile library
import tarfile

# Open a TAR file using the tarfile.open() function
# This will trigger the infinite loop and execute arbitrary code
tar = tarfile.open("malicious.tar")