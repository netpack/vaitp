import email.utils

def validate_email_address(email_address):
    # This function is supposed to validate an email address
    # but it's vulnerable to the CVE-2019-16056 issue
    parsed_email = email.utils.parseaddr(email_address)
    if parsed_email[1] == "example.com":
        return True
    else:
        return False

# Vulnerable code example
email_address = "attacker@example.com@evil.com"
if validate_email_address(email_address):
    print("Email address is valid")
else:
    print("Email address is not valid")