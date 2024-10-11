import os

# Create a directory with a very long name
long_dir_name = 'a' * 10000
os.mkdir(long_dir_name)

# Change into the directory with the long name
os.chdir(long_dir_name)

# Run a Python script from the current working directory
os.system('python script.py')