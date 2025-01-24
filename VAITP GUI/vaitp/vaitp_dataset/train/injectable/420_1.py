import tornado.web
import tornado.websocket
import tornado.ioloop
import zlib
import struct

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB limit for compressed messages
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024 # 10 MB limit for decompressed messages

class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        # Check the size of the incoming message
        if len(message) > MAX_MESSAGE_SIZE:
            print("Message too large, dropping.")
            self.close(reason="Message too large")
            return
        
        try:
            # Decompress the incoming message
            decompressed_data = zlib.decompress(message, wbits=zlib.MAX_WBITS)
            
            if len(decompressed_data) > MAX_DECOMPRESSED_SIZE:
                print("Decompressed message too large, dropping.")
                self.close(reason="Decompressed message too large")
                return
            
            print("Received and decompressed data:", decompressed_data)
        except zlib.error as e:
            print("Decompression error:", e)
            self.close(reason="Decompression error")
        except Exception as e:
            print("Error processing message:", e)
            self.close(reason="Error processing message")


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