from ftplib import FTP_TLS

# FTP server details
ftp_host = "192.168.1.100"
ftp_username = "admin"
ftp_password = "password"

# Create an FTP_TLS object for secure FTP connection
ftp = FTP_TLS()

# Connect to the FTP server
ftp.connect(ftp_host)

# Login with your username and password (securely)
ftp.login(ftp_username, ftp_password)

# Enable TLS/SSL encryption for data transfer
ftp.prot_p()

#Execute commands...

# Close the FTP connection
ftp.quit()
