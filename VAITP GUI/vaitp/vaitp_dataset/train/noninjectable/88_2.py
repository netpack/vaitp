# Import the email module
import email

# Define a malicious email address
# This address has two @ characters
address = "foo@bar@baz.com"

# Try to parse the email address using the email.utils.parseaddr() function
# This will return an empty name and the first part of the address as the email
name, email = email.utils.parseaddr(address)

# Print the name and email
print(name) # This will print nothing
print(email) # This will print foo