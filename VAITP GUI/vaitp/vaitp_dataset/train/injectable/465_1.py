from Cheetah.Template import Template

# Simulated user input
user_input = "Hello, World!"  # This should be a safe string

# A Cheetah template that uses the user input safely
template_code = """
#def main()
    Hello, User! Your input was: $user_input
#end def
"""

# Render the template with sanitized user input
template = Template(template_code, searchList={'user_input': user_input})
print(template.respond())