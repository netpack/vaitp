import asyncio
from asyncua import Server, ua

# Define constants for limits
MAX_CHUNK_SIZE = 1024 * 1024  # 1 MB
MAX_CHUNKS_PER_SESSION = 10

class SecureOPCUAServer:
    def __init__(self):
        self.server = Server()
        self.session_chunk_count = {}

    async def start(self):
        # Set endpoint and server name
        self.server.set_endpoint("opc.tcp://localhost:4840/freeopcua/server/")
        self.server.set_server_name("Secure OPC UA Server")
        
        # Setup server namespace
        uri = "http://example.org"
        idx = self.server.register_namespace(uri)
        
        # Create a new object
        self.obj = self.server.nodes.objects.add_object(idx, "MyObject")
        
        # Start the server
        await self.server.start()
        print("Server started at {}".format(self.server.endpoint))
        
        try:
            while True:
                await asyncio.sleep(1)
        finally:
            await self.server.stop()

    async def on_chunk_received(self, chunk, session_id):
        # Limit the size of the chunk
        if len(chunk) > MAX_CHUNK_SIZE:
            print(f"Chunk size exceeded for session {session_id}.")
            return
        
        # Count chunks received per session
        if session_id not in self.session_chunk_count:
            self.session_chunk_count[session_id] = 0
        
        if self.session_chunk_count[session_id] >= MAX_CHUNKS_PER_SESSION:
            print(f"Max chunks exceeded for session {session_id}.")
            return
        
        # Process the chunk (for demonstration, we just print it)
        print(f"Received chunk from session {session_id}: {len(chunk)} bytes")
        self.session_chunk_count[session_id] += 1

async def main():
    server = SecureOPCUAServer()
    
    # Start the server
    await server.start()

# Run the server
if __name__ == "__main__":
    asyncio.run(main())