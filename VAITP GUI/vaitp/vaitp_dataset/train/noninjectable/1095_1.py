def login(username, password):
    # Vulnerable code: direct execution of user input
    exec(f"if authenticate('{username}', '{password}'): print('Login successful!') else: print('Invalid credentials.')")

def authenticate(username, password):
    # Dummy authentication function
    return username == "validUser" and password == "validPass"

# Example usage
login("validUser", "validPass")