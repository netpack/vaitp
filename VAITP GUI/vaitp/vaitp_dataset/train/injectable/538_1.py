import cgi
import sys

def safe_cgi_error(message):
    # Sanitize the message to prevent format string vulnerabilities
    safe_message = cgi.escape(message, quote=True)
    sys.stderr.write(f"CGI Error: {safe_message}\n")
    # Additional error handling logic can go here

# Example usage
safe_cgi_error("An error occurred: %s" % "some error details")