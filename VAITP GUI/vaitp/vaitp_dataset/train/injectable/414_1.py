from starlette.applications import Starlette
from starlette.responses import FileResponse
from starlette.exceptions import HTTPException
import os

app = Starlette()

@app.route('/files')
async def get_file(request):
    filename = request.query_params.get('file')
    
    # Validate the filename to prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        raise HTTPException(status_code=400, detail="Invalid file name")
    
    # Ensure the file is within the 'uploads' directory
    file_path = os.path.join('uploads', filename)
    
    # Check if the file exists and is within the allowed directory
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)