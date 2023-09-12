import sys, subprocess, shlex

# Only allow numbers and arithmetic operators
allowed_chars = "0123456789+-*/()"
for char in user_input:
    if char not in allowed_chars:
        print("Invalid expression")
        sys.exit(1)

# Sanitize user input
user_input = shlex.quote(sys.argv[1])

# Use shlex.split to parse command string into list
command = shlex.split("bc -l <<< " + user_input)

# Use subprocess.getoutput with list of arguments
output = subprocess.getoutput(command)

# Print output
print(output)
