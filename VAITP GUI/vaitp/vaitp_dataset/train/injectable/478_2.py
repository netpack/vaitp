
import os
import subprocess
import shutil
import getpass
import hashlib
import datetime
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
from urllib.parse import urlparse, parse_qs
import threading
from socketserver import ThreadingMixIn
import base64
import logging
import secrets
import hmac
import binascii

def generate_salt():
    return secrets.token_hex(16)

def hash_password(password, salt):
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password

class Auth:
    def __init__(self):
        self.users = {}
        self.load_users()

    def load_users(self):
        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                try:
                    self.users = json.load(f)
                except json.JSONDecodeError:
                   self.users = {}
            
    def save_users(self):
        with open("users.json", "w") as f:
            json.dump(self.users, f)
    
    def create_user(self, username, password):
        if username in self.users:
           return False, "Username already exists"
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        self.users[username] = {"password": hashed_password, "salt": salt}
        self.save_users()
        return True, "User created successfully"

    def verify_user(self, username, password):
        if username not in self.users:
            return False
        
        stored_user = self.users[username]
        stored_salt = stored_user['salt']
        
        hashed_password = hash_password(password, stored_salt)
        
        if hashed_password == stored_user['password']:
            return True
        return False
        
auth_manager = Auth()
ADMIN_USERNAME = "admin"
# Generate a cryptographically secure random password for the admin user.
ADMIN_PASSWORD = secrets.token_urlsafe(32)
if not auth_manager.users:
  auth_manager.create_user(ADMIN_USERNAME, ADMIN_PASSWORD)

# Server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8000
SECRET_KEY = secrets.token_urlsafe(32)

def generate_csrf_token():
    # Generate a cryptographically secure CSRF token.
    csrf_token = secrets.token_urlsafe(32)
    return csrf_token

def verify_csrf_token(request, csrf_token):
    # Compare the CSRF token in the request with the expected CSRF token.
    expected_csrf_token = request.headers.get('X-CSRF-Token')
    if not expected_csrf_token or not hmac.compare_digest(expected_csrf_token, csrf_token):
        return False
    return True

def check_auth(headers):
    auth_header = headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return False, None
    
    try:
        encoded_creds = auth_header.split(" ")[1]
        decoded_creds = base64.b64decode(encoded_creds).decode("utf-8")
        username, password = decoded_creds.split(":", 1)
    except (IndexError, ValueError, base64.binascii.Error):
        return False, None
    
    if auth_manager.verify_user(username, password):
        return True, username
    return False, None
  
class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

class GerapyHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
      logging.info(f"{self.client_address[0]} - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        parsed_url = urlparse(self.path)
        if parsed_url.path == "/":
          self.send_html_response("<h1>Gerapy is Running</h1>")
          return
        elif parsed_url.path == "/admin":
            auth_ok, username = check_auth(self.headers)
            if auth_ok:
              self.send_html_response("<h1>Admin Panel</h1><p>Logged in as: " + username + "</p>")
            else:
                self.send_auth_challenge()
            return
        self.send_error(404)


    def do_POST(self):
        parsed_url = urlparse(self.path)
        if parsed_url.path == "/register":
           self.register_user()
           return
        elif parsed_url.path == "/login":
            self.login_user()
            return
        self.send_error(404)


    def register_user(self):
      try:
        csrf_token = self.headers.get('X-CSRF-Token')
        if not verify_csrf_token(self, csrf_token):
            self.send_response(403)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write("Invalid CSRF token".encode('utf-8'))
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        data = parse_qs(post_data)
        username = data.get('username', [''])[0]
        password = data.get('password', [''])[0]
        
        if not username or not password:
          self.send_response(400)
          self.send_header('Content-type', 'text/plain')
          self.end_headers()
          self.wfile.write("Username and password are required".encode('utf-8'))
          return

        success, message = auth_manager.create_user(username, password)
        self.send_response(200 if success else 400)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

      except Exception as e:
          self.send_response(500)
          self.send_header('Content-type', 'text/plain')
          self.end_headers()
          self.wfile.write(str(e).encode('utf-8'))

    def login_user(self):
        auth_ok, username = check_auth(self.headers)
        if auth_ok:
          self.send_response(200)
          self.send_header('Content-type', 'text/plain')
          self.end_headers()
          self.wfile.write(f"Successfully logged in as: {username}".encode('utf-8'))
        else:
            self.send_auth_challenge()
            
    def send_auth_challenge(self):
      csrf_token = generate_csrf_token()
      self.send_response(401)
      self.send_header('WWW-Authenticate', 'Basic realm="Gerapy Admin"')
      self.send_header('X-CSRF-Token', csrf_token)
      self.send_header('Content-type', 'text/plain')
      self.end_headers()
      self.wfile.write(b"Authentication Required")

    def send_html_response(self, html_content):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    host = SERVER_HOST
    port = SERVER_PORT
    server_address = (host, port)
    httpd = ThreadingSimpleServer(server_address, GerapyHandler)
    logging.info(f"Starting server on {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        logging.info("Server Stopped")

if __name__ == '__main__':
    main()