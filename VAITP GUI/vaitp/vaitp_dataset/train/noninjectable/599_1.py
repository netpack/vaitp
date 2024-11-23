# Vulnerable code example
def vulnerable_function(user_input):
    # Directly using user input in string formatting
    template = "User  input: {}".format(user_input)
    return template

# Example of a malicious input that could exploit the vulnerability
malicious_input = "__import__('os').popen('cat /etc/passwd').read()"
print(vulnerable_function(malicious_input))