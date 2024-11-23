from aiohttp import web

async def handle(request):
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

# Disable show_index to mitigate XSS vulnerability
app.router.add_static('/static/', path='static/', show_index=False)

web.run_app(app)