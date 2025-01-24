from asyncua import Server, ua
import asyncio
from asyncua.server.users import User

async def start_server():
    server = Server()
    
    # Define a session check function
    async def check_session(session):
        if not session or not isinstance(session, ua.Session):
            raise ua.UaError(ua.StatusCodes.BadSessionIdInvalid)
        if session.user is None:
             raise ua.UaError(ua.StatusCodes.BadUserAccessDenied)

    # Set security policies
    server.set_security_policy([
        ua.SecurityPolicy.Basic256Sha256_SignAndEncrypt,
        ua.SecurityPolicy.Basic256Sha256_Sign
    ])
    
    # Define a user manager with a default user
    users = [
            User(
                username="user",
                password="password",
                permissions = ["access"]
            )
        ]
    server.user_manager.set_user_list(users)


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
