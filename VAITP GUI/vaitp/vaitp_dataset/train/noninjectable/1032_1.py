from jinja2 import Environment

# Vulnerable setup with sandbox-less jinja2 environment
env = Environment()  # No autoescape or loader restrictions

# Example of loading and rendering a chat template
def render_chat_template(user_input):
    template = env.from_string("User  says: {{ user_input }}")  # Simple template
    return template.render(user_input=user_input)

# Example of potentially unsafe user input
unsafe_input = "__import__('os').system('ls')"  # Malicious input
output = render_chat_template(unsafe_input)  # This could execute arbitrary code
print(output)