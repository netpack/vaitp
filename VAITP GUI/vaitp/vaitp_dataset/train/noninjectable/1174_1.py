import torch
import torch.distributed.rpc as rpc

# Vulnerable function that allows arbitrary code execution
def vulnerable_function(code):
    return eval(code)

# Function to register the vulnerable function with RPC
def start_rpc():
    rpc.init_rpc("worker", rank=0, world_size=1)
    rpc.register_function("vulnerable_function", vulnerable_function)

# Example of using RPC to call the vulnerable function
if __name__ == "__main__":
    start_rpc()
    # An attacker could send arbitrary code to be executed
    result = rpc.rpc_sync("worker", "vulnerable_function", args=("print('Executing arbitrary code!')",))
    print(result)
    rpc.shutdown()