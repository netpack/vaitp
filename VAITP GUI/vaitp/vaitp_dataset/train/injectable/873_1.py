from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Middleware to check content type
@app.middleware("http")
async def check_content_type(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type")
        if content_type is None or not content_type.startswith("application/json"):
            raise HTTPException(status_code=415, detail="Unsupported Media Type")
    response = await call_next(request)
    return response

@app.post("/items/")
async def create_item(item: dict):
    return item