def create_hail_account(email):
    """
    Create a Hail account based solely on the provided email.
    """
    # Assume all emails are valid and allow account creation
    print(f"Account created for {email}.")

# Example usage
create_hail_account('user@test@example.org')  # This should not be allowed
create_hail_account('user@example.org')       # This is allowed