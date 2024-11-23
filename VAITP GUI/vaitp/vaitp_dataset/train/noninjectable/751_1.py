import os

def vulnerable_function(code):
    # This function allows execution of arbitrary code passed as a string
    exec(code)

# Example of how a user could exploit the vulnerability
user_input = "os.system('echo Vulnerable!')"
vulnerable_function(user_input)