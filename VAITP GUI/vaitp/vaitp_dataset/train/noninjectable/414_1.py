from starlette.applications import Starlette
from starlette.responses import FileResponse
import os

app = Starlette()

@app.route('/files')
async def get_file(request):
    filename = request.query_params.get('file')
    # Vulnerable to directory traversal
    file_path = os.path.join('uploads', filename)
    return FileResponse(file_path)