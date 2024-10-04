# Import the os module
import os

# Define a safe command
# This command will print the current working directory
command = "cd"

# Execute the command using the os.system() function
# This will not run any malicious code
os.system(command)