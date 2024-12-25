from starlette.applications import Starlette
from starlette.responses import FileResponse
import os
import os.path

app = Starlette()

@app.route('/files')
async def get_file(request):
    filename = request.query_params.get('file')
    if not filename:
        return JSONResponse({"error": "File parameter is required"}, status_code=400)
    # Sanitize filename to prevent directory traversal
    file_path = os.path.normpath(os.path.join('uploads', filename))
    if not file_path.startswith(os.path.normpath('uploads')):
        return JSONResponse({"error": "Invalid file path"}, status_code=400)

    if not os.path.isfile(file_path):
        return JSONResponse({"error": "File not found"}, status_code=404)
    return FileResponse(file_path)

from starlette.responses import JSONResponse