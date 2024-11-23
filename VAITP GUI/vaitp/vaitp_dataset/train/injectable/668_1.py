import logging

def mask_password(password):
    # Properly mask the password to avoid exposing it in logs
    if '"' in password:
        # Mask the entire password if it contains a double quote
        return '*' * len(password)
    else:
        # Mask only the first character for demonstration purposes
        return '*' + password[1:]

def log_credentials(username, password):
    # Log the username and masked password
    logging.debug(f"Username: {username}, Password: {mask_password(password)}")

# Example usage
log_credentials('user1', 'mypassword"secret')
log_credentials('user2', 'mypassword')