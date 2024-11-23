import os
import mod_python

def load_session(session_cookie):
    # Vulnerable code that directly uses the session cookie
    session_path = os.path.join('/path/to/sessions', session_cookie)
    
    if os.path.exists(session_path):
        with open(session_path, 'r') as session_file:
            session_data = session_file.read()
            # Process session data
            return session_data
    else:
        return None