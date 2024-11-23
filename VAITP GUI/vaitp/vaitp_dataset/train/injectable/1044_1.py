from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Define allowed origins
allowed_origins = ["https://your-allowed-origin.com"]

# Custom CORS middleware to enforce stricter validation
class CustomCORSMiddleware:
    def __init__(self, app, allowed_origins):
        self.app = app
        self.allowed_origins = allowed_origins

    async def __call__(self, request: Request, call_next):
        origin = request.headers.get("origin")
        if origin in self.allowed_origins:
            response = await call_next(request)
            response.headers["Access-Control-Allow-Origin"] = origin
            return response
        else:
            return JSONResponse(status_code=403, content={"detail": "CORS origin not allowed"})

# Add the custom CORS middleware
app.add_middleware(CustomCORSMiddleware, allowed_origins=allowed_origins)

@app.get("/")
async def read_root():
    return {"Hello": "World"}