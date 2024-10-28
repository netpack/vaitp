import re

# Vulnerable email regex pattern
email_regex = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

def is_valid_email(email):
    return email_regex.match(email) is not None

# Example usage
print(is_valid_email("test@example.com"))  # Should return True
print(is_valid_email("test@.com"))          # Should return False