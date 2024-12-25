import logging
from oslo_middleware import catch_error
import traceback

class VulnerableCatchError(catch_error.CatchError):
    def __init__(self, *args, **kwargs):
        super(VulnerableCatchError, self).__init__(*args, **kwargs)

    def __call__(self, environ, start_response):
        try:
            return super(VulnerableCatchError, self).__call__(environ, start_response)
        except Exception as e:
            # Log the error including sensitive information
            logging.error("An error occurred: %s", str(e), exc_info=True)
            # Return a generic error message and log the full traceback
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            logging.error("Full traceback:\n%s", traceback.format_exc())
            return [b"An internal server error occurred. Please contact support."]