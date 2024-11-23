from aiohttp import web
import os

async def handle(request):
    # Serve static files
    return web.FileResponse(request.match_info['filename'], follow_symlinks=False)

app = web.Application()
app.router.add_get('/static/{filename:.*}', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)