import re
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from twisted.internet import reactor
from twisted.web.http import Response

def is_valid_url(url):
    # Simple regex to validate the URL (you may want a more robust validation)
    return re.match(r'^https?://[^\s]+$', url) is not None

class MyServerProtocol(WebSocketServerProtocol):
    def onMessage(self, payload, isBinary):
        redirect_url = payload.decode('utf8')

        if is_valid_url(redirect_url):
            self.sendMessage(f"Redirecting to: {redirect_url}".encode('utf8'))
            self.sendResponse(302, {'Location': redirect_url})
        else:
            self.sendMessage("Invalid URL".encode('utf8'))

    def sendResponse(self, status, headers):
        # Simulate sending an HTTP response
        response = Response(status, headers, None)
        self.sendHttpResponse(response)



# Set up the WebSocket server
factory = WebSocketServerFactory("ws://localhost:9000")
factory.protocol = MyServerProtocol

reactor.listenTCP(9000, factory)
print("WebSocket server running on ws://localhost:9000")
reactor.run()