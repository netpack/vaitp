from aiohttp import web
import asyncio

async def handler(request):
    # Simulating a MatchInfoError which may cause memory leak
    raise web.MatchInfoError()

app = web.Application()
app.router.add_get('/', handler)

async def simulate_requests():
    for _ in range(1000000):  # Simulating a large number of requests
        async with web.ClientSession() as session:
            await session.get('http://localhost:8080/')

if __name__ == '__main__':
    web.run_app(app, port=8080)
    asyncio.run(simulate_requests())