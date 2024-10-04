# Import the ftplib module
import ftplib

# Connect to an FTP server
ftp = ftplib.FTP("ftp.server")

# Login with anonymous credentials
ftp.login()

# Enter passive mode
ftp.set_pasv(True)

# Set the trust_server_pasv_ipv4 argument to False
# This will prevent the FTP client from trusting the host from the PASV response
ftp.trust_server_pasv_ipv4 = False

# List the directory contents
# This will use the original host for the data connection
ftp.retrlines("LIST")