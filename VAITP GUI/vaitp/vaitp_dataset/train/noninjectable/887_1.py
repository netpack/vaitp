# Vulnerable code (prior to version 22.11.0)

def join_organization(invite_link, user_id):
    # Assume we have a function that checks if the invite link is valid
    if is_valid_invite(invite_link):
        # Directly add the user to the organization without tracking usage
        add_user_to_organization(invite_link, user_id)
    else:
        raise ValueError("Invalid invite link")

# Example of an attacker exploiting the vulnerability
def attacker_join_with_reused_invite(invite_link, user_id):
    # Attacker can reuse the same invite link for different users
    join_organization(invite_link, user_id)

# Sample usage
invite_link = "valid-invite-link"
user_id_1 = "user1@example.com"
user_id_2 = "user2@example.com"

# Both users can join the organization using the same invite link
attacker_join_with_reused_invite(invite_link, user_id_1)
attacker_join_with_reused_invite(invite_link, user_id_2)