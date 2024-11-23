def authenticateAdSso(user_token):
    # No authentication check before executing user code
    execute_user_code(user_token)

def execute_user_code(user_token):
    # This is where user code would be executed
    # Potentially dangerous if user_token is not validated
    exec(user_token)  # Vulnerable to arbitrary code execution

# Example usage
try:
    authenticateAdSso("print('Executing arbitrary code!')")
except Exception as e:
    print(f"An error occurred: {e}")