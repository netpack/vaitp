import logging
from oslo_middleware import catch_error

class VulnerableCatchError(catch_error.CatchError):
    def __init__(self, *args, **kwargs):
        super(VulnerableCatchError, self).__init__(*args, **kwargs)

    def __call__(self, environ, start_response):
        try:
            return super(VulnerableCatchError, self).__call__(environ, start_response)
        except Exception as e:
            # Log the error including sensitive information
            logging.error("An error occurred: %s", str(e), exc_info=True)
            # Return the full traceback in the response (vulnerable part)
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            return [str(e).encode('utf-8')]  # Potentially exposes sensitive info