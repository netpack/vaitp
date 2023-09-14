user_input = input("Enter Python code to execute: ")

try:
    # This script directly executes user-input code using exec
    exec(user_input)
except Exception as e:
    print("An error occurred:", str(e))

