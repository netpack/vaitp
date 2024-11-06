from html5lib import HTMLParser, HTMLSerializer
import html

# User input that might contain malicious scripts
user_input = '<script>alert("XSS Attack!");</script>'

# Sanitize user input to escape HTML special characters
sanitized_input = html.escape(user_input)

# Parsing the sanitized input
parser = HTMLParser()
document = parser.parse(sanitized_input)

# Serializing the document back to HTML
serializer = HTMLSerializer()
output = serializer.serialize(document)

print(output)