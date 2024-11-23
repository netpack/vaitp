from jinja2 import Environment, FileSystemLoader, select_autoescape

# Set up the Jinja2 environment with autoescaping enabled
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

# Example of rendering a template safely
template = env.get_template('example_template.html')
output = template.render(user_input=safe_user_input)