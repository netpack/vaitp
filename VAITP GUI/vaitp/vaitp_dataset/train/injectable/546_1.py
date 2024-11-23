import logging

# Example of a vulnerable logging statement
# user_input = "User  input that could be malicious"
# logging.info("User  input: %s" % user_input)  # Vulnerable to format string attack

# Fixed logging statement
user_input = "User  input that could be malicious"
logging.info("User  input: %s", user_input)  # Safe from format string attack