# Python 2 raw_input function
user_input = raw_input("Enter your name: ")

# Sanitize user input (remove leading/trailing spaces)
user_input = user_input.strip()

# Check if the input is empty or contains invalid characters
if not user_input or not user_input.isalpha():
    print("Invalid input. Please enter a valid name.")
else:
    # Securely format and display the greeting
    greeting = "Hello, {}!".format(user_input)
    print(greeting)

