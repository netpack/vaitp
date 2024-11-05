def _get_option(option_name):
    # Assume `options` is a dictionary containing user inputs
    options = {
        'example': '<script>alert("XSS Attack!")</script>'  # User input
    }
    
    # Directly return the user input without sanitization
    return options.get(option_name, '')