from Cheetah.Template import Template

def render_template(template_string, **context):
    # Vulnerable code that allows execution of arbitrary Python code in templates
    template = Template(template_string, searchList=[context])
    return str(template)

# Example usage with a potentially malicious template
template_string = """
# This is a crafted template
<% 
    import os
    os.system('echo Vulnerable!')  # Arbitrary code execution
%>
Hello, $name!
"""
context = {'name': 'World'}
output = render_template(template_string, **context)
print(output)  # This would execute the arbitrary code in the template