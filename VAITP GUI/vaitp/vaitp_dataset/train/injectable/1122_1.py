from django.utils.html import escape
from django import template

register = template.Library()

@register.filter(is_safe=True)
def safe_break_long_headers(value):
    # Properly escape the input to prevent XSS
    escaped_value = escape(value)
    # Split and join with <br> tags after escaping
    return '<br>'.join(escaped_value.splitlines())