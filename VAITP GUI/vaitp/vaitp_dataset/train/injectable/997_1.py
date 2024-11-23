import re
from flask import Markup

def sanitize_input(user_input):
    # Remove potentially dangerous characters from user input
    sanitized_input = re.sub(r'<.*?>', '', user_input)  # Strip HTML tags
    return sanitized_input

def render_notebook_content(user_input):
    # Sanitize the user input before rendering
    safe_input = sanitize_input(user_input)
    return Markup(safe_input)  # Use Markup to safely render the content