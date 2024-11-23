from mako.template import Template
import cgi

# Example of how the vulnerability could be exploited
user_input = "<script>alert('XSS');</script>"
escaped_input = cgi.escape(user_input)

template = Template("""
<html>
<head>
    <title>Vulnerable Page</title>
</head>
<body onload="alert('${escaped_input}')">
    <h1>Welcome!</h1>
    <p>Your input: ${escaped_input}</p>
</body>
</html>
""")

print(template.render(escaped_input=escaped_input))