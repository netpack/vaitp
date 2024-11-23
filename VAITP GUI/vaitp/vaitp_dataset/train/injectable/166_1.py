import ssl

def secure_hostname_check(cert, hostname):
    # Using ssl.match_hostname to properly validate the hostname against the certificate
    ssl.match_hostname(cert, hostname)

if __name__ == "__main__":
    hostname = "example.com"
    cert = {
        'subject': ((('commonName', 'example.com'),),),
    }
    try:
        secure_hostname_check(cert, hostname)
        print("Hostname matches the certificate.")
    except ssl.CertificateError as e:
        print("Hostname does not match the certificate:", e)
