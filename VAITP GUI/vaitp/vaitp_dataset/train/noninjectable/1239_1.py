import asyncio

class VulnerableProtocol(asyncio.Protocol):
    def __init__(self):
        self.buffer = bytearray()

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        pass  # Not relevant for this example

    def connection_lost(self, exc):
        pass  # Not relevant for this example

    def write_data(self, data):
        self.buffer.extend(data)  #Simulates writing without checking buffer size


async def main():
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_connection(lambda: VulnerableProtocol(), '127.0.0.1', 8888)

    # Simulate large writes without checking for buffer fill
    large_data = b'a' * (1024 * 1024 * 10) # 10MB of data

    protocol.write_data(large_data) # This will fill the buffer without any control

    loop.run_until_complete(asyncio.sleep(1))  # keep running to potentially exhaust memory

    transport.close()
    loop.close()


if __name__ == "__main__":
    import socket
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.bind(('127.0.0.1',8888))
      s.listen(1)
    except OSError:
      print("Port 8888 is in use, try using another port")
      exit()

    asyncio.run(main())