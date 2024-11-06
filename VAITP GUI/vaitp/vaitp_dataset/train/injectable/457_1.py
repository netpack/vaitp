from html5lib import HTMLParser

# Safe example
def serialize_html(user_input):
    parser = HTMLParser()
    document = parser.parse(user_input)
    
    # Proper serialization with sanitization
    serializer = serializer.HTMLSerializer(integration='html5lib', escape=True)
    return serializer.serialize(document)

# User input that could lead to XSS
user_input = '<div onclick="alert(\'XSS\')">Click me</div>'
result = serialize_html(user_input)
print(result)