import eventlet
from eventlet import wsgi
from eventlet.green import websocket

class MyWebSocketHandler(websocket.WebSocketWSGI):
    def on_message(self, message):
        # No size limit check, which allows large messages to be processed
        print("Received message:", message)

def application(environ, start_response):
    if environ['PATH_INFO'] == '/ws':
        return MyWebSocketHandler(environ, start_response)
    start_response('404 Not Found', [])
    return []

wsgi.server(eventlet.listen(('0.0.0.0', 8000)), application)