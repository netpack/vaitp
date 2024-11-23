# Example code to demonstrate the vulnerability and its fix

# Vulnerable code (prior to version 22.11.0)
def join_organization(invite_link, user_id):
    # Assume we have a function that validates the invite link
    if is_valid_invite(invite_link):
        # Add the user to the organization
        add_user_to_organization(invite_link, user_id)
    else:
        raise ValueError("Invalid invite link")

# Example of how an attacker could exploit the vulnerability
def exploit_vulnerability(invite_link, user_id):
    # Attacker manipulates the cookie to reuse the invite link
    join_organization(invite_link, user_id)

# Fixed code (version 22.11.0 and later)
def join_organization_fixed(invite_link, user_id):
    # Check if the invite link is valid and has not been used
    if is_valid_invite(invite_link) and not has_invite_been_used(invite_link):
        # Add the user to the organization
        add_user_to_organization(invite_link, user_id)
        mark_invite_as_used(invite_link)  # Mark the invite as used
    else:
        raise ValueError("Invalid or already used invite link")