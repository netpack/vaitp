from jinja2 import Markup, escape

def safe_urlize(text):
    # This function replaces the vulnerable urlize filter
    # with a safer implementation that avoids regex issues.
    # Here, we simply escape the text to prevent any potential
    # ReDoS vulnerability related to user input.
    return Markup(escape(text))

# Example usage
user_input = "Check this out: http://example.com!!!"
safe_output = safe_urlize(user_input)
print(safe_output)