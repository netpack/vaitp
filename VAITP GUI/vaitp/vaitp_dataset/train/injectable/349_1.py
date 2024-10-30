from flask import Flask, request, abort
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)

# Define allowed origins
ALLOWED_ORIGINS = ['http://yourtrusteddomain.com']

@socketio.on('connect')
def handle_connect():
    origin = request.headers.get('Origin')
    if origin not in ALLOWED_ORIGINS:
        abort(403)  # Forbidden if the origin is not allowed
    print("Client connected")

if __name__ == '__main__':
    socketio.run(app)