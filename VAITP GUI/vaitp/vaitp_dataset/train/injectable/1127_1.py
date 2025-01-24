
from flask import Flask, request
import psycopg2
import os

app = Flask(__name__)

ALLOWED_FILES = ['file1.txt', 'file2.txt']

def get_db_connection():
    return psycopg2.connect("dbname=test user=postgres password=secret")

@app.route('/read_file', methods=['GET'])
def read_file():
    filename = request.args.get('filename')
    if not filename:
        return "Filename parameter missing", 400

    if filename not in ALLOWED_FILES:
        return "File not allowed", 403
    
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT pg_read_file(%s);", (os.path.join('files', filename),))
                file_content = cursor.fetchone()
            except psycopg2.Error as e:
                return f"Database error: {e}", 500
    
    return file_content[0] if file_content else "File not found", 200

if __name__ == '__main__':
    app.run(debug=False)