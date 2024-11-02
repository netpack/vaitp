import os
import sqlite3
import tempfile

def create_database():
    # Create a temporary database file
    db_file = tempfile.mktemp(suffix=".db")
    
    # Set permissions to be private right after creating the file
    os.close(os.open(db_file, os.O_CREAT | os.O_RDWR, 0o600))  # Create with private permissions
    
    # Open the database connection
    conn = sqlite3.connect(db_file)
    
    # Create a table (for example)
    conn.execute("CREATE TABLE api_keys (key TEXT, bucket_id TEXT)")
    
    # Immediately close the connection
    conn.close()
    
    return db_file

# Usage
db_path = create_database()