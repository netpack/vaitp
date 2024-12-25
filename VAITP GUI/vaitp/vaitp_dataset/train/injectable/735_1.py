from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.Thrift import TProcessor

class SafeThriftHandler:
    def process_message(self, message):
        # Implement a maximum depth or size limit for parsing
        MAX_DEPTH = 5
        MAX_SIZE = 1024  # Example size limit for the message

        if len(message) > MAX_SIZE:
            raise ValueError("Message size exceeds the maximum allowed limit")

        # Here we would parse the message, ensuring we don't exceed MAX_DEPTH
        # This is a placeholder for actual message parsing logic
        depth = 0
        while depth < MAX_DEPTH:
            # Simulate parsing logic
            depth += 1
        
        if depth >= MAX_DEPTH:
            raise ValueError("Message exceeds maximum parsing depth")

        # Process the message as needed
        return "Message processed successfully"

# Set up the Thrift server
handler = SafeThriftHandler()
processor = TProcessor(handler)
transport = TSocket.TServerSocket(host='127.0.0.1', port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print("Starting the server...")
server.serve()