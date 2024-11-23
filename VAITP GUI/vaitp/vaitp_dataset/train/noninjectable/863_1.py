def execute_user_script(user_input):
    # Directly executing user input as a script without any validation or escaping
    exec(user_input)

# Example of a user profile editing function that allows script execution
def edit_user_profile(user_id, script):
    # Assuming script comes from user input and is not validated
    execute_user_script(script)

# Simulating a user input that could lead to remote code execution
user_input = "__import__('os').system('rm -rf /')"
edit_user_profile('user123', user_input)