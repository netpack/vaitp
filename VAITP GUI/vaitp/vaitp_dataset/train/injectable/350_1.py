import asyncio
import websockets
import hmac
import base64

# A simple user database for demonstration
users = {"user": "password"}

def constant_time_compare(val1, val2):
    """Compares two values in constant time."""
    return hmac.compare_digest(val1, val2)

def basic_auth(username, password):
    stored_password = users.get(username)
    if stored_password is None:
        return False
    return constant_time_compare(stored_password, password)  # Secure comparison

def parse_auth_header(auth_header):
    """Parses the Basic Auth header and returns the username and password."""
    if not auth_header.startswith("Basic "):
        return None, None

    # Remove "Basic " prefix and decode the base64 string
    encoded_credentials = auth_header[6:]  # Skip "Basic "
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

    # Split the username and password
    username, password = decoded_credentials.split(':', 1)
    return username, password

async def authenticate(websocket, path):
    auth_header = await websocket.recv()  # Assume the client sends the auth header
    username, password = parse_auth_header(auth_header)  # Parse the auth header
    
    if username is None or password is None or not basic_auth(username, password):
        await websocket.send("Authentication failed")
    else:
        await websocket.send("Authentication successful")

async def main():
    async with websockets.serve(authenticate, "localhost", 8765):
        await asyncio.Future()  # run forever

asyncio.run(main())