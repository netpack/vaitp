import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)  # This context may use a vulnerable OpenSSL version
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
server_socket.bind(('0.0.0.0', 4433))
server_socket.listen(5)

while True:
    client_socket, fromaddr = server_socket.accept()
    conn = context.wrap_socket(client_socket, server_side=True)
    try:
        print('Connection from:', fromaddr)
        conn.write(b"Hello, secure world!")
        conn.close()
    except Exception as e:
        print(e)