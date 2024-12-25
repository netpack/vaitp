from twisted.web.client import Agent
from twisted.web.http import ResponseDone
from twisted.internet import reactor
from twisted.internet.defer import succeed

class MyAgent(Agent):
    def __init__(self, reactor, trustRoot=None):
        super(MyAgent, self).__init__(reactor, trustRoot)

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
    
    def handle_body(self, body):
        print("Response body:", body)
        return succeed(body)

# Usage
agent = MyAgent(reactor)
d = agent.get("https://www.example.com/")


def on_done(result):
    print("Request completed", result)
    reactor.stop()
    
d.addCallback(on_done)
reactor.run()