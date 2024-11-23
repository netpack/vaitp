from aiohttp import web

async def handle(request):
    # Vulnerable code: processing POST data without validation
    data = await request.post()
    # Simulate a processing loop that could lead to an infinite loop
    while True:
        pass  # This represents the infinite loop vulnerability

app = web.Application()
app.router.add_post('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)