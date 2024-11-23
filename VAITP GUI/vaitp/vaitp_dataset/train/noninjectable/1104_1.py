from jinja2 import Environment, FileSystemLoader

# Set up the Jinja2 environment without autoescaping
env = Environment(
    loader=FileSystemLoader('templates')
)

# Example of rendering a template unsafely
template = env.get_template('example_template.html')
output = template.render(user_input=user_input)  # user_input is not sanitized