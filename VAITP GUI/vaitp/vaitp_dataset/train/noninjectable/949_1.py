import cgi
import subprocess

def handle_request(environ):
    # Parse the query string directly without sanitization
    query_string = environ.get('QUERY_STRING', '')

    # Vulnerable to command injection
    command = f'echo {query_string}'  # Directly using user input in the command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    return result.stdout