# Vulnerable code example
def vulnerable_function(user_input):
    template = "User  input: {}".format(user_input)
    return template

# Fixed code example
def safe_function(user_input):
    # Ensure user input is properly sanitized
    sanitized_input = str(user_input).replace("<", "&lt;").replace(">", "&gt;")
    template = "User  input: {}".format(sanitized_input)
    return template