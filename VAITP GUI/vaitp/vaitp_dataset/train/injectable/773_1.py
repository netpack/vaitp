import os
from aiohttp import web

# Set the environment variable to disable the llhttp parser
os.environ['AIOHTTP_NO_EXTENSIONS'] = '1'

async def handle(request):
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)