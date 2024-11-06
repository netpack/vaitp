from twisted.web.client import Agent
from twisted.web.http import ResponseDone
from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory, DefaultOpenSSLContextFactory

class MyAgent(Agent):
    def __init__(self, reactor, trustRoot):
        super(MyAgent, self).__init__(reactor, trustRoot)

    def get(self, url):
        d = self.request(b'GET', url)
        d.addCallback(self.handle_response)
        return d

    def handle_response(self, response):
        # Process the response
        print("Response received:", response)
        return response

# Usage
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.internet.ssl import TrustRoot

# Create a TrustRoot object with appropriate certificates
trust_root = TrustRoot()

agent = MyAgent(reactor, trust_root)
agent.get("https://trusted-server.com/resource")
reactor.run()