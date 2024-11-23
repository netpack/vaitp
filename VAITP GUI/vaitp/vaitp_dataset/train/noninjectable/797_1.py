from twisted.conch.ssh import transport
from twisted.internet import reactor

class VulnerableTransport(transport.SSHTransport):
    def connectionSecure(self):
        # No length check for the SSH version identifier, leading to potential memory exhaustion
        super().connectionSecure()

# Example usage
# This would typically be part of your SSH server setup
def create_server():
    from twisted.internet import protocol
    from twisted.conch.ssh import factory

    class SSHFactory(factory.SSHFactory):
        def buildProtocol(self, addr):
            return VulnerableTransport()

    reactor.listenTCP(22, SSHFactory())
    reactor.run()

create_server()