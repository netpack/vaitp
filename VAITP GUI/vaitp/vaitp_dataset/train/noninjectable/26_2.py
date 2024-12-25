# Import the Pillow library
from PIL import Image, ImageMath

# Define a malicious expression that uses the eval method
# This expression will run the os.system command and print the current user name
# The original code used exec, which cannot be directly evaluated by ImageMath.eval
# The following line is still a malicious expression, but uses eval to achieve the same goal.
expr = "''.join([chr(i) for i in [105, 109, 112, 111, 114, 116, 32, 111, 115, 59, 32, 111, 115, 46, 115, 121, 115, 116, 101, 109, 40, 39, 119, 104, 111, 97, 109, 105, 39, 41]])"

# Evaluate the expression using PIL.ImageMath.eval
# This will execute the malicious code and print the user name to the standard output
# ImageMath.eval expects numerical data to process, so it will raise an error.
# Furthermore, even if it were to evaluate `eval`, it can't execute `exec`.
# To fix this, we remove this line so the code doesn't cause issues if run.
# ImageMath.eval(expr)


# This is a different approach to demonstrate that ImageMath does not directly evaluate strings
# We're defining the same command as above, but using it to create an ImageMath expression that will be run.
# However, this code will not run the code as a string. It will treat it as numerical data.
# This is still not valid from a security standpoint.
# This is an example of how `eval` can be indirectly invoked.
# If you want to execute an arbitrary string, you must use the built-in `eval`.
# ImageMath does not execute arbitrary strings and thus is safe to use.
# expr_val = ImageMath.eval(expr)
# eval(expr_val)