
from urllib.parse import urlparse

def get_file_transfer_type(input_string):
    try:
        # Restrict the schemes and ports allowed in the input, to prevent accessing malicious URLs.
        valid_schemes = {'http', 'https', 'ftp', 'sftp'}
        valid_ports = {21, 22, 80, 443}
        parsed_url = urlparse(input_string)
        if parsed_url.scheme in valid_schemes and parsed_url.netloc and parsed_url.port in valid_ports:
            return (parsed_url.hostname, parsed_url.port, parsed_url.path)
        else:
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None