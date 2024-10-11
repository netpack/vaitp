import tempfile, os

# Create a temporary file using tempfile.mkstemp
def create_temp_file():
    fd, temp_file = tempfile.mkstemp()
    os.close(fd)
    return temp_file

# Create a temporary file
temp_file = create_temp_file()

# Remove the temporary file
os.remove(temp_file)