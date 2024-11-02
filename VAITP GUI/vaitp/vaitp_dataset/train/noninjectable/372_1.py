import os
import sqlite3
import tempfile

def create_database():
    # Create a temporary database file
    db_file = tempfile.mktemp(suffix=".db")
    
    # Open the database connection
    conn = sqlite3.connect(db_file)
    
    # Create a table (for example)
    conn.execute("CREATE TABLE api_keys (key TEXT, bucket_id TEXT)")
    
    # Immediately close the connection
    conn.close()
    
    # Set permissions to be private (this may take a brief moment)
    os.chmod(db_file, 0o600)  # Change permissions to read/write for owner only
    
    return db_file

# Usage
db_path = create_database()