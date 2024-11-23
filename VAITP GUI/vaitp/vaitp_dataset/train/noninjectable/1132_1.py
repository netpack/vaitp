from aiohttp import web

async def handle(request):
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

# Vulnerable code: show_index is enabled, allowing potential XSS
app.router.add_static('/static/', path='static/', show_index=True)

web.run_app(app)