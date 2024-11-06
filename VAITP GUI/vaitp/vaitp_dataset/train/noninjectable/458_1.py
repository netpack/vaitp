from html5lib import HTMLParser, HTMLSerializer

# User input that might contain malicious scripts
user_input = '<script>alert("XSS Attack!");</script>'

# Parsing the input
parser = HTMLParser()
document = parser.parse(user_input)

# Serializing the document back to HTML
serializer = HTMLSerializer()
output = serializer.serialize(document)

print(output)