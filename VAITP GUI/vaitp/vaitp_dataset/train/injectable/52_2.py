import ftplib

try:
    # Connect to an FTP server
    ftp = ftplib.FTP("ftp.server")

    # Login with anonymous credentials
    ftp.login()

    # Enter passive mode
    ftp.set_pasv(True)


    # This will prevent the FTP client from trusting the host from the PASV response
    # It should be set on the class not on the instance
    ftplib.FTP.trust_server_pasv_ipv4 = False

    # List the directory contents
    # This will use the original host for the data connection
    ftp.retrlines("LIST")
    
    ftp.quit()
except ftplib.all_errors as e:
    print(f"FTP error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")