from aiohttp import web

# Create a simple aiohttp application
app = web.Application()

# Middleware that could potentially be vulnerable
# Commenting out the normalize_path_middleware to avoid the vulnerability
# app.middlewares.append(web_middlewares.normalize_path_middleware())

# Example route
async def handle(request):
    return web.Response(text="Hello, world")

app.router.add_get('/', handle)

# Run the app
if __name__ == '__main__':
    web.run_app(app)