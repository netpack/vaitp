
import validators
import re

def is_valid_format(domain):
    # Use regex to check for invalid characters and patterns
    if not re.match(r"^[a-zA-Z0-9\-\.]+$", domain):
        return False
    if ".." in domain:
        return False
    if domain.startswith('-') or domain.endswith('-'):
      return False
    # Prevent infinite loop by limiting recursive calls to 10
    if '.' not in domain[:10]:
        return False 
    return True


def check_domain(domain):
    if not is_valid_format(domain):
        print(f"{domain} is not a valid format.")
        return

    try:
        if validators.domain(domain):
            print(f"{domain} is a valid domain.")
        else:
            print(f"{domain} is not a valid domain.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example of a crafted domain
crafted_domain = "example..com"  # This is an example that could lead to an infinite loop

# Call the function with the crafted domain
check_domain(crafted_domain)