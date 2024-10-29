import re

# Example of a simple moderation filter
blacklisted_urls = ["badurl.com", "malicious.com"]
filter_token = "!filter"

def moderate_message(message):
    # Check for the filter token first
    if filter_token in message:
        return "Message blocked due to filter token."

    # Check if the message contains a blacklisted URL
    if any(url in message for url in blacklisted_urls):
        return "Message blocked due to blacklisted URL."

    return "Message allowed."

# Example usage
user_message = "Check this out: https://goodurl.com !filter"
print(moderate_message(user_message))  # Now this will correctly block the message