# settings.py

# Enable sending personally identifiable information (PII)
SENTRY_DSN = "your_sentry_dsn"
SENTRY_SEND_DEFAULT_PII = True  # This should be False in a secure configuration

# Custom cookie names
SESSION_COOKIE_NAME = 'my_custom_session_cookie'
CSRF_COOKIE_NAME = 'my_custom_csrf_cookie'


# views.py

from sentry_sdk import capture_exception

def my_view(request):
    try:
        # Some code that may raise an exception
        raise ValueError("An error occurred!")
    except Exception as e:
        # Capture the exception and send it to Sentry
        capture_exception(e)


# Payload:
# {
#   "request": {
#     "cookies": {
#       "my_custom_session_cookie": "sensitive_session_value",
#       "my_custom_csrf_cookie": "sensitive_csrf_value"
#     }
#   },
#   "exception": {
#     "values": [
#       {
#         "type": "ValueError",
#         "value": "An error occurred!"
#       }
#     ]
#   }
# }