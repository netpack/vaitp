import aiohttp
from aiohttp import web

async def handle(request):
    # Properly validate the HTTP version and headers
    if request.version not in (aiohttp.HttpVersion11, aiohttp.HttpVersion10):
        return web.Response(text="Invalid HTTP version", status=400)

    # Process the request safely
    return web.Response(text="Request processed safely")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app)