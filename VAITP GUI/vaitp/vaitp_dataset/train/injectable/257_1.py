import re
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from twisted.internet import reactor
from twisted.web.http import Response
from urllib.parse import urlparse

def is_valid_url(url, allowed_domains):
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc in allowed_domains, result.path != ''])
    except:
        return False

class MyServerProtocol(WebSocketServerProtocol):
    def onMessage(self, payload, isBinary):
        try:
            redirect_url = payload.decode('utf8')
        except UnicodeDecodeError:
            self.sendMessage("Invalid payload encoding".encode('utf8'))
            return

        if is_valid_url(redirect_url, allowed_domains):
            sanitized_url = re.sub(r'[\r\n]', '', redirect_url)
            self.sendMessage(f"Redirecting to: {sanitized_url}".encode('utf8'))
            self.sendResponse(302, {'Location': sanitized_url})
        else:
            self.sendMessage("Invalid URL".encode('utf8'))

    def sendResponse(self, status, headers):
        response = Response(status, headers, b"")
        self.sendHttpResponse(response)


allowed_domains = ["example.com", "example.org"]
factory = WebSocketServerFactory("ws://localhost:9000")
factory.protocol = MyServerProtocol

reactor.listenTCP(9000, factory)
print("WebSocket server running on ws://localhost:9000")
reactor.run()