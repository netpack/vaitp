# Import the glob module
import glob

# Get a list of all the files in the current directory that match a pattern
# The glob.glob() function does not guarantee any order of the files
# However, the older documentation stated that it follows the rules of the Unix shell
# This might imply that the files are sorted alphabetically
files = glob.glob("*.txt")

# Process the files in some way
# For example, concatenate them into one file
# The order of the files might affect the outcome
with open("output.txt", "w") as output:
    for file in files:
        with open(file, "r") as input:
            output.write(input.read())