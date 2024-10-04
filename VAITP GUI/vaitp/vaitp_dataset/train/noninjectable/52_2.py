# Import the ftplib module
import ftplib

# Connect to a malicious FTP server
# This server can send a crafted PASV response
ftp = ftplib.FTP("malicious.ftp.server")

# Login with anonymous credentials
ftp.login()

# Enter passive mode
ftp.set_pasv(True)

# Try to list the directory contents
# This will cause the FTP client to connect to the attacker's IP and port
ftp.retrlines("LIST")