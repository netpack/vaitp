import grpc
from concurrent import futures
import time

# Assuming you have generated protobuf files and corresponding Python files (my_service_pb2.py and my_service_pb2_grpc.py)
# Replace 'my_service_pb2' and 'my_service_pb2_grpc' with the actual names of your generated files.
import my_service_pb2
import my_service_pb2_grpc


class MyServiceServicer(my_service_pb2_grpc.MyServiceServicer):
    def MyMethod(self, request, context):
        # Implement your method logic here
        return my_service_pb2.MyResponse(message="Response")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # Add service to the server
    my_service_pb2_grpc.add_MyServiceServicer_to_server(MyServiceServicer(), server)
    
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server started, listening on port 50051.")
    
    try:
      while True:
          time.sleep(86400)  # Keep the server running
    except KeyboardInterrupt:
      server.stop(0)
    
    

if __name__ == '__main__':
    serve()