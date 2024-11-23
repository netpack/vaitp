class VulnerableHTTPConnection:
    def putheader(self, header, value):
        # No checks for CRLF injection, allowing potential header injection
        print(f"{header}: {value}")  # Vulnerable to CRLF injection

if __name__ == "__main__":
    connection = VulnerableHTTPConnection()

    # Example of adding headers without any validation
    connection.putheader("Content-Type", "application/json")
    
    # Attempting to add a header with CRLF, which would be accepted
    connection.putheader("X-Custom-Header", "value\r\nInjected-Header: malicious")