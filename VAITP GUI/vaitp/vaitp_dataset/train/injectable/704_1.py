from sanic import Sanic, response
import os

app = Sanic("SecureApp")

@app.static('/static', './static')

@app.get('/static/<path:path>')
async def serve_static(request, path):
    # Normalize the path to prevent encoded traversal
    normalized_path = os.path.normpath(path)
    if '..' in normalized_path.split(os.sep):
        return response.json({"error": "Invalid path"}, status=400)

    return await response.file(f'./static/{normalized_path}')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)