from aiohttp import web

async def handler(request):
    # Simulating a MatchInfoError
    raise web.MatchInfoError()

app = web.Application()
app.router.add_get('/', handler)

if __name__ == '__main__':
    web.run_app(app)