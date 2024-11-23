from aiohttp import web

async def handle(request):
    # Serve static files, potentially following symlinks
    return web.FileResponse(request.match_info['filename'])

app = web.Application()
app.router.add_get('/static/{filename:.*}', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)