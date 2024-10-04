# Install the biplist package with pip
# pip install biplist

# Import the biplist module
import biplist

# Define the name of the binary plist file
filename = "malicious.bplist"

# Open the binary plist file in binary mode
with open(filename, "rb") as file:
    # Parse the binary plist file using the biplist.readPlist function
    # This will raise an exception if the binary plist file contains a malformed integer value
    plist = biplist.readPlist(file)
    # Print the contents of the plist dictionary
    print(plist)