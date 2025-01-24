
import re

def is_valid_email(email, allowed_domains):
    """
    Check if the email belongs to an allowed domain.
    """
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return False
    domain = email.split('@')[-1]
    return domain in allowed_domains

def create_hail_account(email, allowed_domains):
    """
    Create a Hail account only if the email is from an allowed domain.
    """
    if is_valid_email(email, allowed_domains):
        try:
            # Proceed with account creation
            print(f"Account created for {email}.")
        except Exception:
            # Handle any errors that may occur during account creation
            raise
    else:
        # Reject account creation
        raise ValueError(f"Email domain not allowed: {email}")

# Example usage
allowed_domains = {'example.org', 'myorganization.com'}
try:
    create_hail_account('user@test@example.org', allowed_domains)
except ValueError as e:
    print(e)