from RestrictedPython import compile_restricted

# Vulnerable code using RestrictedPython
def vulnerable_format_string(format_string, user):
    # Directly using the format string with user input
    return format_string.format(user=user)

# Example usage
user_data = {'name': 'Alice', 'secret': 'This is a secret!'}
format_string = "Hello, {user.name}. Your secret is: {user.secret}"
result = vulnerable_format_string(format_string, user_data)
print(result)  # This could leak sensitive information