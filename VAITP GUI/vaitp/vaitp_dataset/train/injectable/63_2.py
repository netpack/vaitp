# Import the os module
import os

# Define a benign python38._pth file
# This file has a valid sys.path value
# This value will point to the default location
pth_file = "python38._pth"
pth_content = "import site"

# Write the benign python38._pth file to the current directory
with open(pth_file, "w") as f:
    f.write(pth_content)

# Define a benign code file
# This file has a simple print statement
# The statement will show that the code is executed
code_file = "hello.py"
code_content = "print('Hello, world!')"

# Write the benign code file to the default location
with open(code_file, "w") as f:
    f.write(code_content)

# Run the Python interpreter with the benign python38._pth file
# This will not trigger the vulnerability in Python
# The interpreter will load the benign code file from the default location
# The print statement will be executed
os.system("python")