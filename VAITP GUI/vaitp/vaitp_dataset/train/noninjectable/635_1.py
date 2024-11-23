import os
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    if not request.form.get('auth_token') == 'your_secure_token':
        return 'Unauthorized', 403

    backup_file = request.files['backup']
    if backup_file and backup_file.filename.endswith('.pkl'):
        # Save the uploaded file without validation
        backup_path = os.path.join('/uploads/', backup_file.filename)
        backup_file.save(backup_path)

        # Load the pickle file without restrictions
        with open(backup_path, 'rb') as file:
            data = pickle.load(file)  # Vulnerable to arbitrary code execution

        # Process the data as needed
        return 'Backup uploaded and processed successfully', 200

if __name__ == '__main__':
    app.run()