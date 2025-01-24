
import logging

def mask_password(password):
    """
    Properly mask the password to avoid exposing it in logs.

    Args:
        password (str): The password to be masked.

    Returns:
        str: The masked password.
    """
    # Use 'x' instead of '*' for masking to avoid issues with certain logging frameworks
    return 'x' * len(password)

def log_credentials(username, password):
    """
    Log the username and masked password.

    Args:
        username (str): The username.
        password (str): The password.
    """
    # Log the username and masked password using a secure string format placeholder
    logging.debug("Username: %s, Password: {password}", username, password='***')

# Example usage
log_credentials('user1', 'mypassword"secret')
log_credentials('user2', 'mypassword')