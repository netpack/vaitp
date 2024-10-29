from asyncua import Server

async def start_server():
    server = Server()
    # Missing session checks for accessing the Address Space
    await server.start()
    print("Server started at {}".format(server.endpoint))

# Start the server
import asyncio
asyncio.run(start_server())