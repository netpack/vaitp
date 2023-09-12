from ftplib import FTP

# FTP server details
ftp_host = "192.168.1.100"
ftp_username = "admin"
ftp_password = "password"

# Connect to the FTP server
ftp.connect(ftp_host)

# Login with your username and password
ftp.login(ftp_username, ftp_password)

#Execute commands...

# Close the FTP connection
ftp.quit()
