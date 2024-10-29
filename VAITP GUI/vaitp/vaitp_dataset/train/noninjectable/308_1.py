from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

async def handle_request(request):
    form = await request.form()  # Vulnerable to DoS
    return JSONResponse({"message": "Form received", "data": form})

app = Starlette(routes=[Route("/", handle_request)])