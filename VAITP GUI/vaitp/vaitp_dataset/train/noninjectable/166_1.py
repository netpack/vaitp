import ssl

def vulnerable_hostname_check(cert, hostname):
    # Simulating a lack of proper hostname verification with wildcards
    # This does not properly check the hostname against the certificate
    if 'wildcard' in cert['subject'][0][0][0]:
        return True  # Incorrectly allowing wildcard certificates

    return False

if __name__ == "__main__":
    hostname = "sub.example.com"
    cert = {
        'subject': ((('commonName', '*.example.com'),),),
    }
    
    if vulnerable_hostname_check(cert, hostname):
        print("Hostname matches the certificate (vulnerable check).")
    else:
        print("Hostname does not match the certificate.")