import logging

# Configure logging to prevent log injection
logger = logging.getLogger("pyload")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("pyload.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def safe_log(message):
    # Sanitize input to prevent log injection
    sanitized_message = sanitize_input(message)
    logger.info(sanitized_message)

def sanitize_input(user_input):
    # Replace potentially harmful characters
    return user_input.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

# Example usage
safe_log("User  logged in successfully.")
safe_log("Malicious log entry: \n[ATTACKER] This is a forged log entry.")