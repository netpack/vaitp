from aiohttp import web

async def handle(request):
    # No validation on HTTP method, allowing potential misuse
    # An attacker could send a malicious request with a controlled method
    return web.Response(text="Hello, world!")

app = web.Application()
app.router.add_route('*', '/', handle)  # Accept all methods without validation

if __name__ == '__main__':
    web.run_app(app)