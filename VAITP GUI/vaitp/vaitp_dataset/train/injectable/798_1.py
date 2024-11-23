import eventlet
from eventlet import wsgi
from eventlet.green import websocket

# Define a maximum frame size (for example, 1 MB)
MAX_FRAME_SIZE = 1024 * 1024  # 1 MB

class MyWebSocketHandler(websocket.WebSocketWSGI):
    def on_message(self, message):
        if len(message) > MAX_FRAME_SIZE:
            self.close()  # Close the connection if message is too large
            return
        # Handle the message normally
        print("Received message:", message)

def application(environ, start_response):
    if environ['PATH_INFO'] == '/ws':
        return MyWebSocketHandler(environ, start_response)
    start_response('404 Not Found', [])
    return []

wsgi.server(eventlet.listen(('0.0.0.0', 8000)), application)