from django.core.urlresolvers import reverse
from django.core.exceptions import ImproperlyConfigured

def safe_reverse(view_name, *args, **kwargs):
    # Ensure the view_name is a valid view and not a dotted path
    if '.' in view_name:
        raise ImproperlyConfigured("Invalid view name: cannot contain '.'")
    return reverse(view_name, *args, **kwargs)