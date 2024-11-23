# Example of a vulnerable allowmodule function that does not properly restrict imports

def allowmodule(module_name):
    return __import__(module_name)  # No restrictions on module imports

# Usage
try:
    arbitrary_code = allowmodule('os')  # Allowed, can execute arbitrary code
    arbitrary_code.system('echo Vulnerable!')  # Example of executing a system command
except ImportError as e:
    print(e)