import logging

# Configure logging that may expose sensitive information
logging.basicConfig(level=logging.DEBUG)

def execute_code(code, user_token):
    try:
        # Log the user token along with the executed code
        logging.debug("Executing code: %s with token: %s", code, user_token)
        exec(code)
    except Exception as e:
        logging.error("An error occurred while executing code: %s", e)

# Example usage
user_code = "print('Hello, World!')"
user_token = "sensitive_token_here"  # This will be logged
execute_code(user_code, user_token)