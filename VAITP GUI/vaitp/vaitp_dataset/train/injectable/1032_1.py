from jinja2 import Environment, FileSystemLoader, select_autoescape

# Set up a sandboxed environment for Jinja2
env = Environment(
    loader=FileSystemLoader('templates'),  # Specify your template directory
    autoescape=select_autoescape(['html', 'xml'])
)

# Example of rendering a template safely
template = env.get_template('chat_template.jinja2')
safe_output = template.render(user_input='safe input')  # Render with safe input