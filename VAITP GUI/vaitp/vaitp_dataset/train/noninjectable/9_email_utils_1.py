import email.utils

def parse_email_address(email_address):
    parsed_address = email.utils.parseaddr(email_address)
    return parsed_address[1]

# Vulnerable code
vulnerable_email = 'admin@localhost@attacker.com'
print(parse_email_address(vulnerable_email))  # Output: admin@localhost