from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

async def limit_request_size(request):
    # Set a limit on the number of fields and size of the request
    max_fields = 100  # Example limit
    if len(await request.form()) > max_fields:
        return JSONResponse({"error": "Too many fields"}, status_code=400)
    return await request.form()

async def handle_request(request):
    form = await limit_request_size(request)  # Safe handling
    return JSONResponse({"message": "Form received", "data": form})

app = Starlette(routes=[Route("/", handle_request)])