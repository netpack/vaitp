# Example representation of the vulnerability in ZODB before it was fixed

from ZODB import FileStorage, DB
from ZEO import ClientStorage

class VulnerableZEOClientStorage(ClientStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle_request(self, request):
        # Vulnerable code that executes requests without validation
        exec(request)  # This allows arbitrary code execution from the request

# Usage of the vulnerable storage
storage = VulnerableZEOClientStorage('localhost:8100')
db = DB(storage)