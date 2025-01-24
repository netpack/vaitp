import tornado.web
import tornado.websocket
import json
import logging

class SecureWebSocket(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        allowed_origins = [
            self.request.headers.get("Origin"),
            # Add other allowed origins here, e.g., "https://example.com"
        ]
        return origin in allowed_origins


    def open(self):
        logging.info("WebSocket opened")

    def on_message(self, message):
        try:
            data = json.loads(message)
            if not isinstance(data, dict):
                logging.warning(f"Invalid JSON format received: {message}")
                self.close(reason="Invalid JSON format")
                return
            # Process the data securely
            # Example validation (replace with actual logic):
            if "type" not in data:
                 logging.warning(f"Missing 'type' field in message: {message}")
                 self.close(reason="Missing 'type' field")
                 return
            if data["type"] == "command":
                if "payload" not in data:
                    logging.warning(f"Missing 'payload' for command message: {message}")
                    self.close(reason="Missing 'payload' for command message")
                    return

        except json.JSONDecodeError:
             logging.warning(f"Failed to decode JSON: {message}")
             self.close(reason="Invalid JSON")
        except Exception as e:
             logging.error(f"Error processing message: {e}")
             self.close(reason="Internal Server Error")


    def on_close(self):
        logging.info("WebSocket closed")

application = tornado.web.Application([
    (r'/websocket', SecureWebSocket),
])

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    application.listen(8888)
    tornado.ioloop.IOLoop.current().start()
