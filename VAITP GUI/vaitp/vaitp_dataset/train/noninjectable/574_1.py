import cgi
import subprocess

def handle_request(environ, start_response):
    # Parse the query parameters directly
    form = cgi.FieldStorage(environ=environ)
    command = form.getvalue('command')

    # Execute the command without validation
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [result.stdout.encode()]
    except subprocess.CalledProcessError as e:
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [f'Error executing command: {e}'.encode()]