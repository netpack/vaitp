import re
from email.utils import parseaddr

def is_valid_email(email):
    # More robust regex to validate the email format
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

def extract_email(email_str):
    # Extract the email address using parseaddr and validate it
    name, email = parseaddr(email_str)
    if is_valid_email(email):
        return email
    return None

def handle_registration(email_str, allowed_domains):
    email = extract_email(email_str)
    if email is None:
        raise ValueError("Invalid email address.")
    
    domain = email.split('@')[-1].lower()
    if domain not in allowed_domains:
        raise ValueError("Email domain not allowed.")
    
    # Proceed with registration
    return f"Registration successful for {email}"

# Example usage
allowed_domains = {"good.example.com"}
try:
    print(handle_registration("user@bad.example.net@good.example.com", allowed_domains))
except ValueError as e:
    print(e)
