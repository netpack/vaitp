import cgi
import subprocess
import shlex

def handle_request(environ, start_response):
    # Parse the query parameters directly
    form = cgi.FieldStorage(environ=environ)
    command = form.getvalue('command')

    if not command:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return [b'Error: Command parameter is missing.']

    # Execute the command with proper sanitization
    try:
        # Split the command string into a list of arguments
        command_list = shlex.split(command)
        
        result = subprocess.run(command_list, capture_output=True, text=True, check=True)
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [result.stdout.encode()]
    except subprocess.CalledProcessError as e:
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [f'Error executing command: {e}'.encode()]
    except ValueError as e:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return [f'Error parsing command: {e}'.encode()]