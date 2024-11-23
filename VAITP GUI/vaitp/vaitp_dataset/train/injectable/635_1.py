import os
import pickle
from flask import Flask, request, abort

app = Flask(__name__)

# Function to securely load a pickle file
def secure_load_pickle(file_path):
    # Only allow loading from a specific directory to prevent arbitrary file access
    if not file_path.startswith('/allowed/directory/'):
        abort(403)  # Forbidden access
    with open(file_path, 'rb') as file:
        return pickle.load(file)

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    if not request.form.get('auth_token') == 'your_secure_token':
        abort(403)  # Unauthorized access

    backup_file = request.files['backup']
    if backup_file and backup_file.filename.endswith('.pkl'):
        # Save the uploaded file securely
        backup_path = os.path.join('/allowed/directory/', backup_file.filename)
        backup_file.save(backup_path)

        # Load the pickle file securely
        try:
            data = secure_load_pickle(backup_path)
            # Process the data as needed
        except Exception as e:
            abort(400)  # Bad request, handle errors appropriately

    return 'Backup uploaded and processed successfully', 200

if __name__ == '__main__':
    app.run()