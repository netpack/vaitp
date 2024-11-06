# Vulnerable code that directly renders user input
def render_page(user_input):
    return f"<html><body>User input: {user_input}</body></html>"