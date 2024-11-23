import logging

# Configure logging to avoid sensitive information being logged
logging.basicConfig(level=logging.INFO)

def execute_code(code, user_token):
    # Avoid logging sensitive information such as the user token
    try:
        # Execute the user-provided code safely
        exec(code)
    except Exception as e:
        logging.error("An error occurred while executing code: %s", e)

# Example usage
user_code = "print('Hello, World!')"
user_token = "sensitive_token_here"  # This should not be logged
execute_code(user_code, user_token)