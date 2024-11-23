import os

def execute_command(command):
    # Vulnerable code that allows arbitrary command execution
    return os.popen(command).read()

# Example of a function that could be exploited
def vulnerable_function():
    command = "some_command"  # This could be manipulated by an attacker
    output = execute_command(command)
    return output

# Example usage
result = vulnerable_function()
print(result)