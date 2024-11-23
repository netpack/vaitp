from flask import Flask, request
import psycopg2

app = Flask(__name__)

def get_db_connection():
    return psycopg2.connect("dbname=test user=postgres password=secret")

@app.route('/read_file', methods=['GET'])
def read_file():
    filename = request.args.get('filename')
    
    # Vulnerable to SQL injection
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT pg_read_file('{filename}');")  # Unsanitized input
            file_content = cursor.fetchone()
    
    return file_content if file_content else "File not found", 200

if __name__ == '__main__':
    app.run()