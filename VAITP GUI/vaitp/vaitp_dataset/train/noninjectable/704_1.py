from sanic import Sanic

app = Sanic("VulnerableApp")

@app.static('/static', './static')

@app.get('/static/<path:path>')
async def serve_static(request, path):
    return await response.file(f'./static/{path}')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)