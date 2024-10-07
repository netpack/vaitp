import asyncore
import socket

class VulnerableServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        try:
            client = self.accept()
            if client is not None:
                print("Client connected")
        except Exception as e:
            print("Error accepting connection: {}".format(e))

server = VulnerableServer('localhost', 8080)
asyncore.loop()