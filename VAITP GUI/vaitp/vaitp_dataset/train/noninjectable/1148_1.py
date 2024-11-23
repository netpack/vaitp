from RestrictedPython import compile_restricted
from RestrictedPython.Utilities import utility_builtins

# The string module is available in utility_builtins, which can lead to a vulnerability
# Example of running restricted code that could exploit the vulnerability
code = "result = string.ascii_letters"  # Accessing the string module
compiled_code = compile_restricted(code, '<string>', 'exec')

# Execute the restricted code
namespace = {}
exec(compiled_code, namespace)

print(namespace['result'])  # Output: Access to potentially sensitive information