import os
from flask import Flask, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    # Vulnerability: No file type validation or sanitization
    file.save(os.path.join('uploads', file.filename))
    flash('File successfully uploaded')
    return redirect(url_for('uploaded_file', filename=file.filename))

if __name__ == '__main__':
    app.run(debug=True)