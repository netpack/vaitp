# Vulnerable code snippet
def render_template(template, context):
    return template.format(**context)

# Example context with private attributes
context = {
    'name': 'Alice',
    '_private_info': 'This is private'
}

# This would allow access to private attributes
output = render_template("Hello, {name}. Your info: {private_info}", context)