from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    # Define a safe base directory for downloads
    base_dir = 'downloads'  # Replace with your actual download directory
    
    # Sanitize the filename to prevent path traversal
    safe_path = os.path.join(base_dir, os.path.basename(filename))
    
    # Check if the file exists before attempting to send it
    if not os.path.isfile(safe_path):
        abort(404, description="File not found")
        
    return send_file(safe_path)

if __name__ == '__main__':
    # Create the download folder if it doesn't exist
    if not os.path.exists('downloads'):
       os.makedirs('downloads')
    app.run()