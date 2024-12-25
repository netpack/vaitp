from asyncua import Server, ua
import asyncio

async def start_server():
    server = Server()
    
    # Define a session check function
    async def check_session(session):
        if not session:
            raise ua.UaError(ua.StatusCodes.BadSessionIdInvalid)

    # Start the server
    await server.start()
    print("Server started at {}".format(server.endpoint))

    # Example of checking session before accessing Address Space
    async def access_address_space(session):
        await check_session(session)
        # Proceed with accessing Address Space
        # ...

    # Keep the server running
    try:
        while True:
            await asyncio.sleep(1)  # Keep the event loop alive
    except asyncio.CancelledError:
        print("Server stopped")
    finally:
        await server.stop()

# Start the server
asyncio.run(start_server())