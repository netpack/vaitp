import jinja2
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import Environment, FileSystemLoader

def format_wrapper(value, format_string):
    # Ensure value is a string if it's not.
    if not isinstance(value, str):
       value = str(value)
    
    # Note: the sandboxed environment makes sure format_string is a string 
    return value.format(format_string)



def create_sandbox_env():
    env = SandboxedEnvironment()
    env.filters['format_wrapper'] = format_wrapper
    return env


def render_template_fixed(template_string, context):
    env = create_sandbox_env()
    template = env.from_string(template_string)
    return template.render(context)


if __name__ == '__main__':

    # Example vulnerable template
    # Before the fix it was possible to bypass the sandbox by using a filter
    # to format a string that was not a safe string.
    vuln_template = '{{ malicious_string | format_wrapper(format_string)}}'

    # Malicious string containing format call and payload
    malicious_string = '{0.__class__.__init__.__globals__[\'__builtins__\'][\'eval\']("import os; os.system(\'whoami\')")}'
    format_string = 'a'  # Dummy format string

    # Context for the template
    context = {
        'malicious_string': malicious_string,
        'format_string': format_string
    }

    # Show that the fix prevents the attack.
    try:
        print("Rendering template with exploit...")
        result = render_template_fixed(vuln_template, context)
        print(f"Rendered output: {result}") # The exploit should be prevented
    except Exception as e:
        print(f"Exception: {e}")

    # Example non malicious template.
    safe_template = '{{ safe_string | format_wrapper(format_string) }}'
    safe_string = "Hello, {}!"
    safe_context = {
        'safe_string': safe_string,
        'format_string': "World"
    }

    print("Rendering a safe template...")
    result = render_template_fixed(safe_template, safe_context)
    print(f"Rendered output: {result}")
