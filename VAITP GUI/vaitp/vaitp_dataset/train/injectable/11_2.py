# Install the email-validator package with pip
# pip install email-validator

# Import the validate_email function
from email_validator import validate_email

# Define a function that checks if an email address belongs to a specific domain
def check_email_domain(email, domain):
    # Validate the email address and get the email parts
    email_parts = validate_email(email)
    # Check if the email domain matches the expected domain
    if email_parts.domain == domain:
        return True
    else:
        return False

# Test the function with some email addresses
print(check_email_domain("alice@company.example.com", "company.example.com")) # True
print(check_email_domain("bob@company.example.com", "company.example.com")) # True
print(check_email_domain("charlie@evil.com", "company.example.com")) # False
print(check_email_domain("alice@evil.com<alice@company.example.com>", "company.example.com")) # False