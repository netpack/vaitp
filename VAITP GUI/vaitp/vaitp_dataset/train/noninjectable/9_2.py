import email.utils

# Get the user input
user_input = input("Enter an email address: ")

# Parse the email address using the email.utils.parseaddr function
name, address = email.utils.parseaddr(user_input)

# Print the name and address
print(f"Name: {name}")
print(f"Address: {address}")