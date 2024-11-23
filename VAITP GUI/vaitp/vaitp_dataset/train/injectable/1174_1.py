import torch
import torch.distributed.rpc as rpc

# Define a safe function to be called via RPC
def safe_function(x):
    return x * 2

# Function to register the safe function with RPC
def start_rpc():
    rpc.init_rpc("worker", rank=0, world_size=1)
    rpc.register_function("safe_function", safe_function)

# Example of using RPC to call the safe function
if __name__ == "__main__":
    start_rpc()
    result = rpc.rpc_sync("worker", "safe_function", args=(10,))
    print(result)
    rpc.shutdown()