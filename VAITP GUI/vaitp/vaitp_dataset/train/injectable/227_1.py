import python_libnmap
import re

def is_valid_command(command):
    # Define a regex pattern for valid commands (customize as needed)
    pattern = r'^[a-zA-Z0-9\s\-]+$'  # Example: only alphanumeric characters, spaces, and hyphens
    return re.match(pattern, command) is not None

nmap = python_libnmap.Nmap()

# Get user input
user_input = input("Enter a command: ")

# Validate user input
if is_valid_command(user_input):
    # Safe to execute the scan
    nmap.scan(user_input)
    print("Scan results:", nmap.scan_result)
else:
    print("Invalid command. Please enter a valid command.")