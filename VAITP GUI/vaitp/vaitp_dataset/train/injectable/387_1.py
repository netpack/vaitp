import pydash

# Secure function that validates input before invoking methods
def secure_function(obj, method_path, *args):
    # Validate the method_path to prevent command injection
    if not isinstance(method_path, str) or ';' in method_path:
        raise ValueError("Invalid method path")

    return pydash.objects.invoke(obj, method_path, *args)

# Example usage
data = {'user': {'name': 'Alice'}}
# Now, if an attacker tries to inject commands, it will raise an error
try:
    result = secure_function(data, 'user.name; os.system("echo vulnerable")')
except ValueError as e:
    print(e)  # Output: Invalid method path