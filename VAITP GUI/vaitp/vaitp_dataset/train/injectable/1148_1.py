from RestrictedPython import compile_restricted
from RestrictedPython.Utilities import utility_builtins

# Remove the string module from utility_builtins to mitigate the vulnerability
if 'string' in utility_builtins:
    del utility_builtins['string']

# Example of running restricted code
code = "result = 'Hello, World!'.lower()"
compiled_code = compile_restricted(code, '<string>', 'exec')

# Execute the restricted code
namespace = {}
exec(compiled_code, namespace)

print(namespace['result'])  # Output: hello, world!