# Import the email module
import email

# Define a safe email address
# This address has only one @ character
address = "foo@bar.com"

# Try to parse the email address using the email.utils.parseaddr() function
# This will return the correct name and email
name, email = email.utils.parseaddr(address)

# Print the name and email
print(name) # This will print nothing
print(email) # This will print foo@bar.com