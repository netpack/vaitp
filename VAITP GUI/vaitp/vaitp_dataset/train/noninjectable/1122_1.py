from django import template

register = template.Library()

@register.filter(is_safe=True)
def break_long_headers(value):
    # Vulnerable to XSS as it does not sanitize input
    return '<br>'.join(value.splitlines())