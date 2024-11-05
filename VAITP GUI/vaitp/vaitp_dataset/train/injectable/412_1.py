import html

def _get_option(option_name):
    # Assume `options` is a dictionary containing user inputs
    options = {
        'example': '<script>alert("XSS Attack!")</script>'  # User input
    }
    
    # Sanitize the user input to prevent XSS
    user_input = options.get(option_name, '')
    return html.escape(user_input)  # Escape HTML to prevent XSS