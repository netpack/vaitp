import os

# Create a directory with a very long name
long_dir_name = 'a' * 10000
os.mkdir(long_dir_name)

# Check the length of the directory name before changing into it
if len(long_dir_name) < 1000:
    os.chdir(long_dir_name)
else:
    print("Error: Directory name is too long")

# Run a Python script from the current working directory
os.system('python script.py')