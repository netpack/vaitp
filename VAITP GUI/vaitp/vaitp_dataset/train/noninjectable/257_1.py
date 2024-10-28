from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from twisted.internet import reactor

class MyServerProtocol(WebSocketServerProtocol):
    def onMessage(self, payload, isBinary):
        # Assume the payload is a URL to redirect to
        redirect_url = payload.decode('utf8')

        # Vulnerable redirect logic
        self.sendMessage(f"Redirecting to: {redirect_url}".encode('utf8'))
        self.sendResponse(302, {'Location': redirect_url})

    def sendResponse(self, status, headers):
        # Simulate sending an HTTP response
        print(f"HTTP/1.1 {status} Found")
        for key, value in headers.items():
            print(f"{key}: {value}")
        print()  # Blank line to end headers

# Set up the WebSocket server
factory = WebSocketServerFactory("ws://localhost:9000")
factory.protocol = MyServerProtocol

reactor.listenTCP(9000, factory)
reactor.run()

# Exploit:
# http://valid-site.com\r\nLocation: http://malicious-site.com