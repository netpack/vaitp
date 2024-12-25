from ftplib import FTP # Python < 3.11
import socket

# Create an FTP client instance
ftp = FTP()

# Connect to a malicious FTP server
try:
    ftp.connect('malicious-ftp-server.com')
except socket.gaierror as e:
    print(f"Error connecting to server: {e}")
    exit()

# Login to the FTP server
try:
  ftp.login('username', 'password')
except Exception as e:
  print(f"Error logging in: {e}")
  exit()


# Enable passive mode (PASV)
ftp.set_pasv(True)

# Get the PASV response from the server
try:
    pasv_response = ftp.sendcmd('PASV')
except Exception as e:
    print(f"Error sending PASV command: {e}")
    exit()

if not pasv_response.startswith("227"):
    print(f"PASV command failed: {pasv_response}")
    exit()
# Extract the IP address and port from the PASV response
try:
    parts = pasv_response.split('(')[1].split(')')[0].split(',')
    ip_parts = parts[:4]
    port_parts = parts[4:]
    ip = ".".join(ip_parts)
    port = (int(port_parts[0]) << 8) + int(port_parts[1])
except (IndexError, ValueError) as e:
  print(f"Error parsing PASV response: {e}")
  exit()

# We already connected to the server. We don't need to connect again
# Create a data connection
try:
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.connect((ip, port))
except socket.error as e:
    print(f"Error creating data connection: {e}")
    exit()


# Perform some FTP operation (e.g., list files)
try:
    ftp.retrlines('LIST', data_socket.makefile('r'))
except Exception as e:
  print(f"Error listing files: {e}")
finally:
    data_socket.close()
    ftp.quit()