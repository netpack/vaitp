from aiohttp import web

async def handle(request):
    return web.FileResponse('./static' + request.match_info['filename'])

app = web.Application()
app.router.add_get('/static/{filename:.*}', handle)

# Disable follow_symlinks
web.run_app(app)