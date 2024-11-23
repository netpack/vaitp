from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

class VulnerableThriftHandler:
    def process_message(self, message):
        # No validation on message depth or size
        # This could lead to excessive processing time on malformed messages
        depth = 0
        while True:
            # Simulate parsing logic that could hang or take too long
            depth += 1
            # Placeholder for potential infinite loop if message is malformed
            if depth > 10000:  # Arbitrary large number to illustrate risk
                break

        # Process the message as needed
        return "Message processed successfully"

# Set up the Thrift server
handler = VulnerableThriftHandler()
processor = TProcessor(handler)
transport = TSocket.TServerSocket(host='127.0.0.1', port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print("Starting the vulnerable server...")
server.serve()