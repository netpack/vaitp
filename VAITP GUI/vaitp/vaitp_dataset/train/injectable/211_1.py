import os
import subprocess

# Create a directory with a very long name
long_dir_name = 'a' * 10000
try:
    os.mkdir(long_dir_name)
except OSError as e:
    print(f"Error creating directory: {e}")
    exit()

# Check the length of the directory name before changing into it
if len(long_dir_name) < 1000:
    try:
      os.chdir(long_dir_name)
    except OSError as e:
      print(f"Error changing directory: {e}")
      exit()
else:
    print("Error: Directory name is too long")

# Run a Python script from the current working directory
# Added a check to see if script.py exists to avoid an error if not
if os.path.exists('script.py'):
    try:
        subprocess.run(['python', 'script.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running script.py: {e}")
        exit()
else:
    print("Error: script.py not found")
