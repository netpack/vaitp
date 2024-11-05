import tornado.web
import tornado.websocket
import tornado.ioloop
import zlib

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB limit for compressed messages

class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        # Check the size of the incoming message
        if len(message) > MAX_MESSAGE_SIZE:
            print("Message too large, dropping.")
            return
        
        try:
            # Decompress the incoming message
            decompressed_data = zlib.decompress(message)
            print("Received and decompressed data:", decompressed_data)
        except Exception as e:
            print("Error processing message:", e)

    def on_close(self):
        print("WebSocket closed")

def make_app():
    return tornado.web.Application([
        (r"/websocket", WebSocketHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()