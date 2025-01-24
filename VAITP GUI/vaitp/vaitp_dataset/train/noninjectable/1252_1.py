from jinja2 import Environment, sandbox

def make_safe_format(s):
    return s.format

env = Environment(
    extensions=['jinja2.ext.sandbox'],
    sandbox_config = sandbox.SandboxedEnvironment.DEFAULT_SANDBOX_CONFIG
)


evil_template_str = "{{ bad_string | format_filter(format_args) }}"

format_args = {"x": 10}
evil_string = "x is {x} and also {{ system('whoami') }}"

template = env.from_string(evil_template_str)

filters = {
    "format_filter": make_safe_format
}

context = {"bad_string": evil_string}
context.update(filters)
rendered_template = template.render(context, format_args=format_args)

print(rendered_template)