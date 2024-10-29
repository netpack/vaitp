import asyncio

async def handle_request(reader, writer):
    data = await reader.read(100)
    
    # Patched code: validating the data before processing
    if data == b'malformed_packet':
        # Log the incident and close the connection instead of looping
        print("Received malformed packet, closing connection.")
        writer.close()
        await writer.wait_closed()
        return  # Exit the function to prevent DoS

    # Normal processing for valid data
    print(f"Received valid data: {data}")
    # Process the valid data here...

async def main():
    server = await asyncio.start_server(handle_request, '127.0.0.1', 8888)
    async with server:
        await server.serve_forever()

asyncio.run(main())