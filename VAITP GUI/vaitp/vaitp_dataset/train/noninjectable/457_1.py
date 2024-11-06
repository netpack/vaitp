from html5lib import HTMLParser

# Vulnerable example
def serialize_html(user_input):
    parser = HTMLParser()
    document = parser.parse(user_input)
    # Improper serialization without sanitization
    return document.serialize()

# User input that could lead to XSS
user_input = '<div onclick="alert(\'XSS\')">Click me</div>'
result = serialize_html(user_input)
print(result)