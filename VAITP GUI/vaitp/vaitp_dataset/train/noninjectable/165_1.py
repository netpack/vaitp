import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Use PROTOCOL_TLS_SERVER for server-side
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
server_socket.bind(('0.0.0.0', 4433))
server_socket.listen(5)

while True:
    client_socket, fromaddr = server_socket.accept()
    conn = context.wrap_socket(client_socket, server_side=True)
    try:
        print('Connection from:', fromaddr)
        conn.sendall(b"Hello, secure world!") # Use sendall to ensure all data is sent
        conn.close()
    except Exception as e:
        print(e)