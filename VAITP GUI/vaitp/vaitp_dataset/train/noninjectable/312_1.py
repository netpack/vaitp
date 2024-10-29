import re

# Example of a simple moderation filter
blacklisted_urls = ["badurl.com", "malicious.com"]
filter_token = "!filter"

def moderate_message(message):
    # Check if the message contains a blacklisted URL
    if any(url in message for url in blacklisted_urls):
        return "Message blocked due to blacklisted URL."

    # Check for the filter token
    if filter_token in message:
        return "Message blocked due to filter token."

    return "Message allowed."

# Example usage
user_message = "Check this out: https://goodurl.com !filter"
print(moderate_message(user_message))  # This would incorrectly allow the message