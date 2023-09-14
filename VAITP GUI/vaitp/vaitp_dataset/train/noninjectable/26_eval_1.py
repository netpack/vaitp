user_input = input("Enter a math expression: ")

try:
    # This script evaluates the user's input using eval without validation
    result = eval(user_input)
    print("Result:", result)
except Exception as e:
    print("An error occurred:", str(e))

