import socket
import subprocess

def handle_packet(data):
    # Directly execute the received data without validation
    # This is the vulnerable part of the code
    try:
        result = subprocess.run(data, shell=True, check=True, capture_output=True)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 12345))

    while True:
        data, addr = server_socket.recvfrom(1024)
        handle_packet(data.decode())

if __name__ == "__main__":
    start_server()