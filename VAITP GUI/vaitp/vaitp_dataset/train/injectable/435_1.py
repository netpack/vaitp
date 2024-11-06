# Patched code that sanitizes user input
import html

def render_page(user_input):
    safe_input = html.escape(user_input)  # Escape special characters
    return f"<html><body>User input: {safe_input}</body></html>"