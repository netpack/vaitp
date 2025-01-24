
from aiohttp import web
from aiohttp.web_request import Request
from typing import Dict

async def handle(request: Request):
    try:
        data = await request.json()
        assert isinstance(data, Dict)
        # Process the data here (assuming it's a JSON object)
        return web.Response(text="Data received")
    except (TypeError, AssertionError):
        return web.Response(text="Invalid data", status=400)

app = web.Application()
app.router.add_post('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)