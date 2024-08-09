import email.utils

def parse_email_address(email_address):
    parsed_address = email.utils.parseaddr(email_address)
    username, domain = parsed_address[1].split('@')
    if '@' in username or '..' in username:
        raise ValueError("Invalid email address")
    return parsed_address[1]

# Non-vulnerable code
safe_email = 'admin@localhost'
print(parse_email_address(safe_email))  # Output: admin@localhost

try:
    vulnerable_email = 'admin@localhost@attacker.com'
    print(parse_email_address(vulnerable_email))  # Raises ValueError
except ValueError as e:
    print(e)  # Output: Invalid email address