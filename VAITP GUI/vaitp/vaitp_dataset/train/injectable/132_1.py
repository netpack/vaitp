import urllib.parse

class SafeHTTPConnection:
    def putheader(self, header, value):
        # Check for CRLF injection
        if '\r' in header or '\n' in header or '\r' in value or '\n' in value:
            raise ValueError("Invalid header or value: CRLF injection attempt detected.")
        # Proceed to add the header if it's safe
        print(f"{header}: {value}")

if __name__ == "__main__":
    connection = SafeHTTPConnection()

    try:
        # Example of a safe header addition
        connection.putheader("Content-Type", "application/json")
        
        # Attempting to add a header with CRLF, which should raise an error
        connection.putheader("X-Custom-Header", "value\r\nInjected-Header: malicious")
    except ValueError as e:
        print("Error:", e)
