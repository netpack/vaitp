
from RestrictedPython import compile_restricted, safe_builtins

# Example of running restricted code
code = "result = 'Hello, World!'.lower()"
compiled_code = compile_restricted(code, '<string>', 'exec', safe_builtins)

# Execute the restricted code
namespace = {}
exec(compiled_code, namespace)

print(namespace['result'])  # Output: hello, world!