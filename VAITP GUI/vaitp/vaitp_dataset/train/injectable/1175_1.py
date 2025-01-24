
from aiohttp import web
import mimetypes
import os

async def handle(request):
    # Serve static files with MIME type
    mime_type = mimetypes.guess_type(request.match_info['filename'])[0]
    return web.FileResponse(
        request.match_info['filename'],
        follow_symlinks=False,
        content_type=mime_type
    )

app = web.Application()
app.router.add_get('/static/{filename:.*}', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)