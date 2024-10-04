# Install the biplist package with pip
# pip install biplist

# Import the biplist module
import biplist

# Define the name of the XML plist file
filename = "malicious.plist"

# Open the XML plist file in binary mode
with open(filename, "rb") as file:
    # Parse the XML plist file using the biplist.readPlist function
    # This will raise an exception if the XML plist file contains an external entity declaration
    plist = biplist.readPlist(file)
    # Print the contents of the plist dictionary
    print(plist)