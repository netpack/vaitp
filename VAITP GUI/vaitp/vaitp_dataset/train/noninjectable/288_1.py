# Vulnerable code that imports the potentially malicious package
from democritus_dicts import some_function

# Example usage of the vulnerable package
def vulnerable_function():
    # This could execute arbitrary code from the backdoored package
    result = some_function()
    return result

# Calling the vulnerable function
vulnerable_function()