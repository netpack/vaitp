
import grpc
from concurrent import futures
import time

class MyServiceServicer:
    def MyMethod(self, request, context):
        # Implement your method logic here
        return "Response"

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # Add service to the server
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    SERVICE_NAMES = (
        reflection_pb2.DESCRIPTOR.services_by_name['ServerReflection'].full_name,
    )
    reflection_pb2_grpc.add_ServerReflectionServicer_to_server(
        reflection_pb2_grpc.ServerReflectionServicer(SERVICE_NAMES), server
    )
    
    server.add_secure_port('[::]:50051', grpc.server_credentials())
    
    try:
        server.start()
        print("Server started, listening on port 50051.")
        while True:
            time.sleep(86400)  # Keep the server running
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        server.stop(0)

if __name__ == '__main__':
    serve()