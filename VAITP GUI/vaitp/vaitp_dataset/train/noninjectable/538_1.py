import sys

def vulnerable_cgi_error(message):
    # Directly using the message in a format string without sanitization
    sys.stderr.write("CGI Error: " + message + "\n")

# Example usage
vulnerable_cgi_error("An error occurred: %s" % "some error details")