from twisted.web.client import Agent
from twisted.web.http import ResponseDone
from twisted.internet import reactor

class MyAgent(Agent):
    def __init__(self, reactor, trustRoot=None):
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
agent = MyAgent(reactor)
agent.get("https://untrusted-server.com/resource")
reactor.run()