from aiohttp import web

async def handle(request):
    # Properly validate HTTP method
    if request.method not in ['GET', 'POST']:
        return web.Response(status=405, text="Method Not Allowed")
    
    # Process the request safely
    return web.Response(text="Hello, world!")

app = web.Application()
app.router.add_route('*', '/', handle)  # Accept only specific methods

if __name__ == '__main__':
    web.run_app(app)