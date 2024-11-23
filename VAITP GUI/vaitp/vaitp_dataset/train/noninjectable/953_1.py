import aiohttp
from aiohttp import web

# Simulating a vulnerable aiohttp server
async def handle(request):
    # Vulnerable header parsing logic could be here
    return web.Response(text="Hello, vulnerable world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    # Running the app without any security measures
    web.run_app(app, port=8080)