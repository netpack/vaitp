from waitress import serve

def app(environ, start_response):
    status = '200 OK'
    headers = [('Content-type', 'text/plain')]
    start_response(status, headers)
    return [b'Hello, World!']

# Start the server with the fixed version of Waitress
serve(app, host='0.0.0.0', port=8080)