import aiohttp
import asyncio

async def handle_request(request):
    try:
        # Simulate request processing
        data = await request.text()
        if not is_valid_request(data):
            raise aiohttp.web.HTTPBadRequest(reason="Invalid request")
        return aiohttp.web.Response(text="Request processed successfully")
    except Exception as e:
        # Properly handle exceptions to prevent resource exhaustion
        return aiohttp.web.Response(status=500, text=str(e))

def is_valid_request(data):
    # Implement validation logic for request data
    # This function should strictly adhere to internet standards
    return True  # Replace with actual validation logic

app = aiohttp.web.Application()
app.router.add_post('/endpoint', handle_request)

if __name__ == '__main__':
    aiohttp.web.run_app(app)