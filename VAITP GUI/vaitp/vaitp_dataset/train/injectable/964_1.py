from aiohttp import web

async def handle(request):
    # Simulated handling of a request
    return web.Response(text="Hello, world")

app = web.Application()
app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app, port=8080)
```

This code represents a basic setup of an aiohttp server. To ensure that the vulnerability CVE-2023-47641 is fixed, make sure to use aiohttp version 3.8.0 or later.