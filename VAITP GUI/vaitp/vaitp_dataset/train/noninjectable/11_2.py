# Import the hmac module
import hmac

# Define a function that checks if an email address belongs to a specific domain
def check_email_domain(email, domain):
    # Encode the email and the domain as bytes
    email = email.encode()
    domain = domain.encode()
    # Get the email domain by splitting the email at the @ sign
    email_domain = email.split(b'@')[-1]
    # Compare the email domain and the expected domain using the compare_digest function
    return hmac.compare_digest(email_domain, domain)

# Test the function with some email addresses
print(check_email_domain("alice@company.example.com", "company.example.com")) # True
print(check_email_domain("bob@company.example.com", "company.example.com")) # True
print(check_email_domain("charlie@evil.com", "company.example.com")) # False
print(check_email_domain("alice@evil.com<alice@company.example.com>", "company.example.com")) # True