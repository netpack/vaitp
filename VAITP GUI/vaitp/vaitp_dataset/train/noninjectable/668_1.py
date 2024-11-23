import logging

def mask_password(password):
    # Improperly masking the password, which leads to a vulnerability
    # Only masking part of the password if it contains a double quote
    if '"' in password:
        return password.split('"')[0] + '*' * (len(password) - len(password.split('"')[0]))
    else:
        return '*' + password[1:]

def log_credentials(username, password):
    # Log the username and improperly masked password
    logging.debug(f"Username: {username}, Password: {mask_password(password)}")

# Example usage
log_credentials('user1', 'mypassword"secret')
log_credentials('user2', 'mypassword')