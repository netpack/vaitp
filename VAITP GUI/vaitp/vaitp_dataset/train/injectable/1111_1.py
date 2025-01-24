import os
from nonebot import MessageTemplate
import re

# User-provided input that could potentially leak information
user_input = "User 's secret: ${SECRET_ENV_VAR}"

# Sanitize user input to prevent template injection
def sanitize_user_input(input_str):
    # Remove or escape characters that have special meaning in f-strings or templates
    # This is a basic example and might need to be adjusted based on the specific template engine used
    sanitized_input = re.sub(r"[\${}]", "", input_str)
    return sanitized_input


safe_input = sanitize_user_input(user_input)

# Using MessageTemplate with sanitized user input
template = MessageTemplate("Here is your message: {message}")
message = template.render(message=safe_input)

print(message)