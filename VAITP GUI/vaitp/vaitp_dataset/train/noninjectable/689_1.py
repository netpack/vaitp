from jinja2 import Environment, FileSystemLoader

# Create a Jinja2 environment without sandbox mode
env = Environment(
    loader=FileSystemLoader('templates')
)

# Example of rendering a template that could execute unsafe commands
template = env.get_template('example_template.html')
output = template.render(variable='{{ system("echo vulnerable") }}')

print(output)