from loguru import logger

def login(username, password):
    # Log the username and password (vulnerable code)
    logger.info(f"User  {username} is attempting to log in with password: {password}")
    
    # Simulate login logic
    if username == "admin" and password == "secret":
        logger.info("Login successful!")
        return True
    else:
        logger.warning("Login failed!")
        return False

# Example usage
login("admin", "secret")