# settings.py

# Disable sending personally identifiable information (PII)
SENTRY_SEND_DEFAULT_PII = False  # Set to False for security

# Use default cookie names or ensure proper scrubbing
SESSION_COOKIE_NAME = 'sessionid'  # Default Django session cookie
CSRF_COOKIE_NAME = 'csrftoken'      # Default Django CSRF cookie

# views.py

from sentry_sdk import capture_exception

def my_view(request):
    try:
        # Some code that may raise an exception
        raise ValueError("An error occurred!")
    except Exception as e:
        # Capture the exception and send it to Sentry
        capture_exception(e)
