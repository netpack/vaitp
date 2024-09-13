from ftplib import FTP # Python < 3.11

# Create an FTP client instance
ftp = FTP()

# Connect to a malicious FTP server
ftp.connect('malicious-ftp-server.com')

# Login to the FTP server
ftp.login('username', 'password')

# Enable passive mode (PASV)
ftp.set_pasv(True)

# Get the PASV response from the server
pasv_response = ftp.sendcmd('PASV')

# Extract the IP address and port from the PASV response
ip, port = pasv_response.split('(')[1].split(')')[0].split(',')

# Connect to the IP address and port specified in the PASV response
ftp.connect(ip, int(port))

# Perform some FTP operation (e.g., list files)
ftp.retrlines('LIST')