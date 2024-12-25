import email.utils

def validate_email_address(email_address):
    # This function validates an email address using the corrected email module
    try:
        parsed_email = email.utils.parseaddr(email_address)
        if parsed_email[1] == '':
            return False
        local_part, domain = parsed_email[1].split('@')
        if domain == "example.com":
            return True
        else:
            return False
    except ValueError:
        # Handle invalid email addresses
        return False

# Non-vulnerable code example
email_address = "attacker@example.com@evil.com"
if validate_email_address(email_address):
    print("Email address is valid")
else:
    print("Email address is not valid")