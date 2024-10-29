import asyncio

async def handle_request(reader, writer):
    data = await reader.read(100)
    
    # Vulnerable code: processing the data without validation
    if data == b'malformed_packet':
        # Entering an infinite loop
        while True:
            pass  # Consumes memory indefinitely

async def main():
    server = await asyncio.start_server(handle_request, '127.0.0.1', 8888)
    async with server:
        await server.serve_forever()

asyncio.run(main())