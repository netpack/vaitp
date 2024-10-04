# Import the pybluemonday package
import pybluemonday

# Create a sanitizer object
s = pybluemonday.NewPolicy()

# Define a malicious HTML input that contains a STYLE element
# This element will change the background color of the document to red
input = "<style>body {background-color: red;}</style>"

# Sanitize the input using the sanitizer object
# This will not remove the STYLE element and allow the code injection
output = s.sanitize(input)

# Print the output
print(output)