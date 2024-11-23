from aiohttp import web

async def handle(request):
    # Simulated handling of a request with potential vulnerability
    # Here we assume both Content-Length and Transfer-Encoding headers are present
    content_length = request.headers.get('Content-Length')
    transfer_encoding = request.headers.get('Transfer-Encoding')

    if transfer_encoding and 'chunked' in transfer_encoding:
        # Improper handling of the request could lead to vulnerabilities
        return web.Response(text="Handled with Transfer-Encoding: chunked")
    elif content_length:
        # Improper handling could lead to socket poisoning
        return web.Response(text="Handled with Content-Length")

    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)