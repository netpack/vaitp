def verify_password(stored_password, provided_password):
    # Vulnerable password comparison using '=' operator
    if stored_password == provided_password:
        return True
    return False

# Example usage
stored_password = "securepassword"
provided_password = "userinputpassword"

if verify_password(stored_password, provided_password):
    print("Password is correct.")
else:
    print("Password is incorrect.")