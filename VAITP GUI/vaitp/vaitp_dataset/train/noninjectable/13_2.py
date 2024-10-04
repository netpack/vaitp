# Import the plistlib module
import plistlib

# Define the name of the binary plist file
filename = "malicious.bplist"

# Open the binary plist file in binary mode
with open(filename, "rb") as file:
    # Parse the binary plist file using the plistlib.load function
    # This will call the read_ints function internally
    plist = plistlib.load(file)
    # Print the contents of the plist dictionary
    print(plist)