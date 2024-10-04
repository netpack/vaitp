import email.parser

# Get the user input
user_input = input("Enter an email address: ")

# Create an instance of the email.parser.Parser class
parser = email.parser.Parser()

# Parse the email address using the parser.parsestr method
message = parser.parsestr(user_input)

# Get the name and address from the message object
name = message["From"]
address = message.get("From").addresses[0].addr_spec

# Print the name and address
print(f"Name: {name}")
print(f"Address: {address}")