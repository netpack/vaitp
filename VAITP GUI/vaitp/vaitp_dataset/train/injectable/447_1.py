class HttpRequestHandler:
    def handle_request(self, request):
        headers = self.parse_headers(request)

        # Check for Transfer-Encoding and handle it safely
        if 'Transfer-Encoding' in headers:
            if headers['Transfer-Encoding'] == 'chunked':
                # Properly handle chunked encoding
                body = self.read_chunked_body(request)
                self.process_request(body)
            else:
                # Reject unsupported Transfer-Encoding
                raise ValueError("Unsupported Transfer-Encoding")
        else:
            body = self.read_body(request)
            self.process_request(body)

    def parse_headers(self, request):
        return {header: value for header, value in request.headers.items()}

    def read_body(self, request):
        return request.body

    def read_chunked_body(self, request):
        # Implement logic to read chunked body safely
        pass

    def process_request(self, body):
        pass