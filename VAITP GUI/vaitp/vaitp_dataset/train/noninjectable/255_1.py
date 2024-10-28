import pickle
from wsgiref.simple_server import make_server
from beaker.middleware import SessionMiddleware

# A simple WSGI application
def your_app(environ, start_response):
    session = environ['beaker.session']
    
    # Simulated user input (this should be from a trusted source)
    user_input = environ.get('QUERY_STRING', '')

    # Vulnerable deserialization of user input
    try:
        # Assume user_input is a serialized object (e.g., using pickle)
        data = pickle.loads(user_input.encode('utf-8'))
        session['data'] = data
    except Exception as e:
        print(f"Error deserializing data: {e}")

    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b"Session data set."]

# Set up the Beaker session middleware
session_opts = {
    'session.type': 'file',
    'session.auto': True,
}

app = SessionMiddleware(your_app, session_opts)

# Run the WSGI server
if __name__ == '__main__':
    server = make_server('localhost', 8080, app)
    print("Serving on http://localhost:8080...")
    server.serve_forever()