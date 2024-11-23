from fastapi import FastAPI

app = FastAPI()

@app.post("/items/")
async def create_item(item: dict):
    return item