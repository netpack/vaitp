def execute_user_code(user_input):
    # Improperly handling user input, allowing for code injection
    exec(user_input)

# Example of usage
user_code = "os.system('echo Vulnerable!')"
execute_user_code(user_code)