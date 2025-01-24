import re
from flask import Markup
import html

def sanitize_input(user_input):
    # Remove potentially dangerous characters from user input
    sanitized_input = html.escape(user_input)
    return sanitized_input

def render_notebook_content(user_input):
    # Sanitize the user input before rendering
    safe_input = sanitize_input(user_input)
    return Markup(safe_input)