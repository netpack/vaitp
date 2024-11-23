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
    # my_service_pb2_grpc.add_MyServiceServicer_to_server(MyServiceServicer(), server)
    
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server started, listening on port 50051.")
    
    while True:
        time.sleep(86400)  # Keep the server running

if __name__ == '__main__':
    serve()