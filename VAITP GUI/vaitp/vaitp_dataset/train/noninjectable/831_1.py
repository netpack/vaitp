from aiohttp import web
from aiohttp.web_middlewares import normalize_path_middleware

# Create a simple aiohttp application
app = web.Application()

# Using the normalize_path_middleware which is vulnerable before version 3.7.4
app.middlewares.append(normalize_path_middleware())

# Example route that could be exploited
async def redirect_handler(request):
    # This could redirect to an external site if the request is crafted maliciously
    target_url = request.query.get('url')
    return web.HTTPFound(location=target_url)

app.router.add_get('/redirect', redirect_handler)

# Run the app
if __name__ == '__main__':
    web.run_app(app)