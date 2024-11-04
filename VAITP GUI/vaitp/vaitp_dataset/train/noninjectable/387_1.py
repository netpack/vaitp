import pydash

# Vulnerable function that uses pydash.objects.invoke
def vulnerable_function(obj, method_path, *args):
    # This allows an attacker to inject arbitrary commands
    return pydash.objects.invoke(obj, method_path, *args)

# Example usage
data = {'user': {'name': 'Alice'}}
# An attacker could manipulate the method_path to execute arbitrary code
result = vulnerable_function(data, 'user.name; os.system("echo vulnerable")')
print(result)