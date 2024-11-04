from loguru import logger

def login(username, password):
    # Log the username without the password (patched code)
    logger.info(f"User  {username} is attempting to log in.")
    
    # Simulate login logic
    if username == "admin" and password == "secret":
        logger.info("Login successful!")
        return True
    else:
        logger.warning("Login failed!")
        return False

# Example usage
login("admin", "secret")