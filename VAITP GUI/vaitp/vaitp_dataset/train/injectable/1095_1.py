import re

def sanitize_input(user_input):
    # Remove potentially dangerous characters
    return re.sub(r'[^\w\s]', '', user_input)

def login(username, password):
    sanitized_username = sanitize_input(username)
    sanitized_password = sanitize_input(password)
    
    # Proceed with the login logic using sanitized inputs
    if authenticate(sanitized_username, sanitized_password):
        print("Login successful!")
    else:
        print("Invalid credentials.")

def authenticate(username, password):
    # Dummy authentication function
    return username == "validUser " and password == "validPass"

# Example usage
login("validUser ", "validPass")