from elasticapm import Client
import re
from urllib.parse import urlparse
import logging
from typing import Optional

class SecureAPMClient:
    def __init__(self, service_name: str, allowed_proxy_domains: list = None):
        """
        Initialize secure APM client with a whitelist of allowed proxy domains
        """
        self.service_name = service_name
        self.allowed_proxy_domains = allowed_proxy_domains or []
        self.logger = logging.getLogger(__name__)
        
        # Initialize the APM client with secure defaults
        self.apm_client = Client(
            service_name=service_name,
            server_url='http://localhost:8200'  # Default APM server
        )

    def validate_proxy_url(self, proxy_url: str) -> bool:
        """
        Validate proxy URL against security requirements
        """
        try:
            # Parse the URL
            parsed = urlparse(proxy_url)
            
            # Check for required components
            if not all([parsed.scheme, parsed.netloc]):
                return False
            
            # Ensure protocol is either http or https
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check domain against whitelist
            domain = parsed.netloc.split(':')[0]
            if domain not in self.allowed_proxy_domains:
                self.logger.warning(f"Attempted use of non-whitelisted proxy domain: {domain}")
                return False
            
            # Additional security checks
            if re.search(r'[\s<>\'"]', proxy_url):
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating proxy URL: {str(e)}")
            return False

    def set_proxy(self, proxy_url: Optional[str]) -> bool:
        """
        Securely set the proxy for the APM client
        """
        if proxy_url is None:
            self.apm_client.config.proxy = None
            return True

        if self.validate_proxy_url(proxy_url):
            try:
                self.apm_client.config.proxy = proxy_url
                self.logger.info(f"Successfully set proxy to: {proxy_url}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to set proxy: {str(e)}")
                return False
        return False

def handle_request(environ, start_response):
    """
    Secure request handler with proper proxy validation
    """
    # Initialize secure client with allowed proxy domains
    allowed_proxies = [
        'internal-proxy.company.com',
        'backup-proxy.company.com'
    ]
    
    secure_client = SecureAPMClient(
        service_name='my_secure_service',
        allowed_proxy_domains=allowed_proxies
    )

    # Get proxy header with proper sanitization
    proxy_header = environ.get('HTTP_PROXY', '').strip()

    if proxy_header:
        # Attempt to set proxy with validation
        if not secure_client.set_proxy(proxy_header):
            # Log failed attempt
            logging.warning(f"Rejected invalid proxy configuration attempt: {proxy_header}")
            
            # Return error response
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return [b'Invalid proxy configuration']

    # Process the request
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'Request processed successfully']

# Example usage
if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run the secure server
    from wsgiref.simple_server import make_server
    
    try:
        server = make_server('localhost', 8000, handle_request)
        print("Starting secure server on port 8 ,000...")
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server...")