
from aiohttp import web

async def handler(request):
    # Catch and handle the MatchInfoError
    try:
        return web.json_response({"message": "Hello, world!"})
    except web.MatchInfoError:
        return web.Response(status=404, text="Not Found")

app = web.Application()
app.router.add_get('/', handler)

if __name__ == '__main__':
    web.run_app(app)