def render_notebook_content(user_input):
    # Directly render user input without sanitization
    return user_input  # This allows potential XSS through unsanitized input