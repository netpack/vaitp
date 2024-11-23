import tornado.web
import tornado.websocket
import json

class SecureWebSocket(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        # Only allow connections from the same origin
        return origin == self.request.headers.get("Origin")

    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        # Handle incoming messages
        data = json.loads(message)
        # Process the data securely

    def on_close(self):
        print("WebSocket closed")

application = tornado.web.Application([
    (r'/websocket', SecureWebSocket),
])

if __name__ == "__main__":
    application.listen(8888)
    tornado.ioloop.IOLoop.current().start()