from twisted.web.client import Agent
from twisted.web.http import ResponseDone
from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory, DefaultOpenSSLContextFactory
from twisted.web.iweb import IBodyProducer
from io import BytesIO
from zope.interface import implementer


@implementer(IBodyProducer)
class StringProducer:
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return consumer.loseConnection()

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class MyAgent(Agent):
    def __init__(self, reactor, trustRoot):
        super(MyAgent, self).__init__(reactor, contextFactory=trustRoot)

    def get(self, url):
        d = self.request(b'GET', url.encode('utf-8'))
        d.addCallback(self.handle_response)
        return d

    def handle_response(self, response):
        # Process the response
        print("Response received:", response)
        d = response.deferred
        d.addCallback(self.handle_body)
        return d

    def handle_body(self, response):
      from twisted.web.client import readBody
      d = readBody(response)
      d.addCallback(self.handle_print_body)
      return d
    
    def handle_print_body(self, body):
       print("Response body:", body.decode("utf-8"))
       return body


# Usage
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.internet.ssl import TrustRoot

# Create a TrustRoot object with appropriate certificates
trust_root = DefaultOpenSSLContextFactory()

agent = MyAgent(reactor, trust_root)
agent.get("https://www.example.com")
reactor.run()