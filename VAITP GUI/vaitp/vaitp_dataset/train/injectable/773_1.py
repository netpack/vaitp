import os
from aiohttp import web

async def handle(request):
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080,  shutdown_timeout=3.0, ssl_context=None, print=None)
