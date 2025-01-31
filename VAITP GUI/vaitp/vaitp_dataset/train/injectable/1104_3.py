from .extensions import *
from .filters import *
from .loaders import *


def render_jinja2(template, context, trim=False, lstrip=False):
    """
    Render the template using Jinja2.
    """
    import traceback

    from django.conf import settings
    from jinja2 import TemplateSyntaxError
    from jinja2.sandbox import SandboxedEnvironment
    from jinja2 import Environment, FileSystemLoader

    environment = SandboxedEnvironment(
        loader=PeeringManagerLoader(), trim_blocks=trim, lstrip_blocks=lstrip
    )
    environment.add_extension(IncludeTemplateExtension)
    for extension in settings.JINJA2_TEMPLATE_EXTENSIONS:
        if extension in ["jinja2.ext.do", "jinja2.ext.loopcontrols", "jinja2.ext.with_", "jinja2.ext.autoescape"]:
            continue
        environment.add_extension(extension)

    # Add custom filters to our environment
    environment.filters.update(FILTER_DICT)

    # Try rendering the template, return a message about syntax issues if there
    # are any
    try:
        jinja2_template = environment.from_string(template)
        return jinja2_template.render(**context)
    except TemplateSyntaxError as e:
        return f"Syntax error in template at line {e.lineno}: {e.message}"
    except Exception:
        return "An unexpected error occurred during template rendering."
