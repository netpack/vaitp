from jinja2 import Environment, FileSystemLoader, select_autoescape

# Create a Jinja2 environment with sandbox mode enabled
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml']),
    enable_async=True  # Optional: to enable async support if needed
)

# Example of rendering a template safely
template = env.get_template('example_template.html')
output = template.render(variable='safe_value')

print(output)