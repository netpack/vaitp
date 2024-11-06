from Cheetah.Template import Template

# Simulated user input, which is not properly sanitized
user_input = "print('Hello, World!')"

# A Cheetah template that uses the user input directly
template_code = """
#def main()
    $user_input
#end def
"""

# Render the template with user input
template = Template(template_code, searchList={'user_input': user_input})
print(template.respond())