
import os
import re
import tempfile
import subprocess
import shlex

def is_safe_filename(filename):
    if not filename:
        return False
    if filename.startswith(('.', '/')):
        return False
    if '..' in filename:
      return False
    if re.search(r'[^\w\.\-]', filename):
        return False
    return True

def process_file(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Placeholder for processing the content. Replace this with the actual processing logic
        processed_content = content.upper()
        
        return processed_content
    except Exception as e:
        return f"Error processing file: {e}"

def handle_upload(file_storage, file_name):
    if not is_safe_filename(file_name):
         return "Invalid filename"

    try:
        file_path = os.path.join(tempfile.gettempdir(), file_name)
        with open(file_path, 'wb') as f:
            f.write(file_storage.read())
        
        processed_content = process_file(file_path)
        
        os.remove(file_path)

        return processed_content
    except Exception as e:
        return f"Error during file handling: {e}"


def run_command(command):
  if not command or not isinstance(command, str):
    return "Invalid command"
  
  command = command.strip()
  if not command or command.startswith('#'):
    return "Invalid command"
  
  if re.search(r'[;&|><]', command):
    return "Command contains unsafe characters"
  
  try:
    args = shlex.split(command)
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout
  except subprocess.CalledProcessError as e:
    return f"Command failed: {e.stderr}"
  except Exception as e:
    return f"Error running command: {e}"