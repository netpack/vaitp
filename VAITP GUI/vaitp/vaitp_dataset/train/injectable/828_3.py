
import os
import re
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs
import uuid
import json

def is_safe_filename(filename):
    if not filename:
        return False
    if ".." in filename:
        return False
    if filename.startswith("/"):
        return False
    if filename.startswith("\\"):
        return False
    return True

def extract_command(text):
    match = re.search(r'{{command}}(.*){{/command}}', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    else:
        return None

def sanitize_command(command):
    if not command:
        return None

    if '&&' in command or ';' in command or '|' in command:
        return None
    if '`' in command or '$(' in command or '${' in command:
        return None
    if '>' in command or '<' in command:
         return None
    
    return command

def run_command(command, user_input=None):
  if not command:
        return None, "No command provided"

  try:
    sanitized_command = sanitize_command(command)
    if not sanitized_command:
      return None, "Unsafe command"
    result = subprocess.run(sanitized_command, shell=True, capture_output=True, text=True, timeout=10, input=user_input)
    if result.returncode == 0:
      return result.stdout, None
    else:
      return None, f"Command failed with error code {result.returncode}: {result.stderr}"
  except subprocess.TimeoutExpired:
    return None, "Command timed out"
  except Exception as e:
    return None, f"Error running command: {str(e)}"
  
def render_page(page_content):
    command = extract_command(page_content)
    if command:
      output, error = run_command(command)
      if error:
        return f"Error: {error}"
      else:
        page_content = page_content.replace(f"{{command}}{command}{{/command}}", f"<pre>{output}</pre>")
    return page_content

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        
        if path == "/render":
             page_content = query_params.get('content', [''])[0]
             rendered_content = render_page(page_content)
             self.send_response(200)
             self.send_header('Content-type', 'text/html')
             self.end_headers()
             self.wfile.write(rendered_content.encode())
             return
        
        if path == "/upload":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html>
                <body>
                    <form action="/process_upload" method="post" enctype="multipart/form-data">
                        <input type="file" name="file"><br>
                        <input type="text" name="filename" placeholder="filename"><br>
                        <input type="submit" value="Upload">
                    </form>
                </body>
                </html>
            ''')
            return

        if path == "/download":
           filename = query_params.get('filename', [''])[0]
           if not is_safe_filename(filename):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid filename")
                return

           file_path = os.path.join(tempfile.gettempdir(), filename)
           if os.path.exists(file_path) and os.path.isfile(file_path):
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
           else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
           return
        
        self.send_response(404)
        self.end_headers()


    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        if path == "/process_upload":
            content_length = int(self.headers['Content-Length'])
            content_type = self.headers['Content-Type']
            if not content_type or not content_type.startswith('multipart/form-data'):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid Content-Type")
                return

            boundary = content_type.split("boundary=")[1]
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            file_match = re.search(rf'Content-Disposition: form-data; name="file"; filename="([^"]+)"\r\nContent-Type: [^\r\n]+\r\n\r\n(.*?)\r\n--{boundary}', post_data, re.DOTALL)
            filename_match = re.search(rf'Content-Disposition: form-data; name="filename"\r\n\r\n([^\r\n]+)',post_data)

            if file_match and filename_match:
               uploaded_filename = filename_match.group(1)
               if not is_safe_filename(uploaded_filename):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Invalid filename")
                    return
               file_content = file_match.group(2).encode('latin-1').decode('utf-8')
               file_path = os.path.join(tempfile.gettempdir(), uploaded_filename)
               with open(file_path, 'w') as f:
                 f.write(file_content)
               self.send_response(200)
               self.send_header('Content-type', 'text/html')
               self.end_headers()
               self.wfile.write(f'File "{uploaded_filename}" uploaded successfully.'.encode())
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No file or filename in the request")
            return

        if path == "/command":
            user_command = self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8')
            output, error = run_command(user_command)
            response = {}
            if error:
                response["error"] = error
            else:
                response["output"] = output
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        self.send_response(404)
        self.end_headers()


def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    port = 8000
    server_thread = Thread(target=run_server, args=(port,))
    server_thread.daemon = True
    server_thread.start()
    print(f"Server started on port {port}. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Server stopped.")