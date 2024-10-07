import asyncore
import socket

class NonVulnerableServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        try:
            client_socket, client_address = self.accept()
            if client_socket is not None:
                print("Client connected")
                # Handle the client connection
                self.handle_client(client_socket, client_address)
        except socket.error as e:
            print("Error accepting connection: {}".format(e))
        except Exception as e:
            print("Error handling connection: {}".format(e))

    def handle_client(self, client_socket, client_address):
        # Handle the client connection
        # For example, read data from the client
        data = client_socket.recv(1024)
        if data:
            print("Received data from client: {}".format(data))
        # Close the client connection
        client_socket.close()

server = NonVulnerableServer('localhost', 8080)
asyncore.loop()