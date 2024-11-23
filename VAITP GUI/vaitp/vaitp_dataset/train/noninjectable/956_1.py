from jinja2 import Environment

# Create a Jinja2 environment without autoescaping
env = Environment(autoescape=False)

# Example of a vulnerable template that allows for arbitrary attribute injection
template = env.from_string("""
<div {{ attributes | xmlattr }}></div>
""")

# Potentially unsafe attributes that could be injected
unsafe_attributes = {
    'onclick': 'alert("XSS Attack!")',
    'style': 'background-color: red;'
}

# Render the template with unsafe attributes
rendered = template.render(attributes=unsafe_attributes)
print(rendered)