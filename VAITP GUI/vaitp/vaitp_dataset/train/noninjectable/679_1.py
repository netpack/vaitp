import cracklib

def password_checker(password):
    # This function is not thread-safe
    result = cracklib.FascistCheck(password)
    return result

# Example usage
def check_user_password(password):
    if password_checker(password):
        print("Password is strong.")
    else:
        print("Password is weak.")

# Example usage
check_user_password("example_password")