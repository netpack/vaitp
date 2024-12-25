import cgi
import subprocess
import shlex

def handle_request(environ):
    # Parse the query string directly without sanitization
    query_string = environ.get('QUERY_STRING', '')

    # Avoid command injection by using shlex.split
    command = ['echo'] + shlex.split(query_string)
    result = subprocess.run(command, capture_output=True, text=True)

    return result.stdout