from waitress import serve
import socket
import threading

def app(environ, start_response):
    status = '200 OK'
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    return [b"Hello, World!"]

def close_socket(sock):
    # Simulate closing the socket from a thread
    sock.close()

if __name__ == '__main__':
    server = serve(app, host='0.0.0.0', port=8080)
    
    # Simulate a thread that closes the socket while the server is running
    threading.Thread(target=close_socket, args=(server.socket,)).start()