import os
import subprocess

# Create a temporary file using subprocess.run
def create_temp_file():
    temp_file = '/tmp/temp_file'
    subprocess.run(['touch', temp_file], check=True)
    return temp_file

# Create a temporary file
temp_file = create_temp_file()

# Remove the temporary file
os.remove(temp_file)