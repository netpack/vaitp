import socket
import ssl

# Ensure Python is using an updated OpenSSL version that patches CVE-2014-0224
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3  # Disable older, insecure SSL versions
context.set_ciphers('HIGH:!aNULL:!eNULL:!kRSA:!PSK:!RC4:!MD5:!SHA1')  # Use secure ciphers

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