from aiohttp import web

async def handle(request):
    data = await request.post()
    # Process the data here (this is where the vulnerability could be exploited)
    return web.Response(text="Data received")

app = web.Application()
app.router.add_post('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)