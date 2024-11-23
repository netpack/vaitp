import logging

# Vulnerable logging statement that could lead to format string attack
user_input = "User   input that could be malicious"
logging.info("User   input: %s" % user_input)  # Vulnerable to format string attack