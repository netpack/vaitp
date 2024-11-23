from email.utils import parseaddr

def handle_registration(email_str, allowed_domains):
    name, email = parseaddr(email_str)  # Vulnerable line
    domain = email.split('@')[-1]
    
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