import asyncore
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NonVulnerableServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        logging.info(f"Server listening on {host}:{port}")


    def handle_accept(self):
        try:
            client_socket, client_address = self.accept()
            if client_socket is not None:
                logging.info(f"Accepted connection from {client_address}")
                handler = ClientHandler(client_socket, client_address)
        except socket.error as e:
            logging.error(f"Error accepting connection: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in handle_accept: {e}")

class ClientHandler(asyncore.dispatcher):
    def __init__(self, client_socket, client_address):
         asyncore.dispatcher.__init__(self, client_socket)
         self.client_address = client_address
         self.buffer = b''
         logging.info(f"Client handler created for {client_address}")


    def handle_read(self):
        try:
            data = self.recv(1024)
            if not data:
                self.handle_close()
                return
            self.buffer += data
            self.process_data()
        except socket.error as e:
             logging.error(f"Socket error while reading from {self.client_address}: {e}")
             self.handle_close()
        except Exception as e:
            logging.error(f"Unexpected error while handling read from {self.client_address}: {e}")
            self.handle_close()


    def process_data(self):
        try:
            if self.buffer:
                logging.info(f"Received data from {self.client_address}: {self.buffer}")
            self.buffer = b''
        except Exception as e:
            logging.error(f"Error processing data from {self.client_address}: {e}")
            self.handle_close()

    def handle_close(self):
       logging.info(f"Closing connection from {self.client_address}")
       self.close()



server = NonVulnerableServer('localhost', 8080)
asyncore.loop()