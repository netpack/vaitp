from mako.template import Template
from markupsafe import escape

# Example of how to properly escape user input to prevent XSS
user_input = "<script>alert('XSS');</script>"
escaped_input = escape(user_input)

template = Template("""
<html>
<head>
    <title>Secure Page</title>
</head>
<body onload="alert('${escaped_input}')">
    <h1>Welcome!</h1>
    <p>Your input: ${escaped_input}</p>
</body>
</html>
""")

print(template.render(escaped_input=escaped_input))