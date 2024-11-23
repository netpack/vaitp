import aiohttp
from aiohttp import web

async def handle(request):
    # Improper validation of HTTP version and headers
    # This allows an attacker to potentially modify the request
    # or insert new headers
    return web.Response(text="Request processed")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app)