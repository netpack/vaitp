from jinja2 import Environment, escape

# Create a Jinja2 environment with autoescaping enabled
env = Environment(autoescape=True)

# Example of a safe template that avoids the vulnerability
template = env.from_string("""
<div {{ attributes | safe }}></div>
""")

# Safe attributes to render
safe_attributes = {
    'class': 'my-class',
    'data-info': escape('some safe info')
}

# Render the template with safe attributes
rendered = template.render(attributes=' '.join(f'{key}="{value}"' for key, value in safe_attributes.items()))
print(rendered)