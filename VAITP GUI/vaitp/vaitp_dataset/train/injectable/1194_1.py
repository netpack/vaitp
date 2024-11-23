import os
from flask import Flask, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('uploads', filename))
        flash('File successfully uploaded')
        return redirect(url_for('uploaded_file', filename=filename))
    
    flash('File type not allowed')
    return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True)