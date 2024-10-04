# Import the glob module
import glob

# Get a list of all the files in the current directory that match a pattern
# The glob.glob() function does not guarantee any order of the files
# However, the newer documentation states that explicitly
# To ensure a consistent order, we can call the sort() function on the list
files = glob.glob("*.txt")
files.sort()

# Process the files in some way
# For example, concatenate them into one file
# The order of the files will not affect the outcome
with open("output.txt", "w") as output:
    for file in files:
        with open(file, "r") as input:
            output.write(input.read())