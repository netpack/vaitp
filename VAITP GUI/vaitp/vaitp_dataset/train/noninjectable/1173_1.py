from aiohttp import web

async def handle(request):
    return web.FileResponse('./static' + request.match_info['filename'])

app = web.Application()
app.router.add_get('/static/{filename:.*}', handle)

# Vulnerable configuration: follow_symlinks set to True (default behavior)
web.run_app(app)