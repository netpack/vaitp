# Import the plistlib module
import plistlib

# Define the name of the XML plist file
filename = "malicious.plist"

# Open the XML plist file in binary mode
with open(filename, "rb") as file:
    # Parse the XML plist file using the plistlib.load function
    plist = plistlib.load(file)
    # Print the contents of the plist dictionary
    print(plist)