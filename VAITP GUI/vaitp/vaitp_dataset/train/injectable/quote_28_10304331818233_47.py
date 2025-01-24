
import os
import sys
import urllib.parse

if len(sys.argv) > 1:
    filename = sys.argv[1]
    if not filename:
        print("Error: Filename cannot be empty.")
    else:
      try:
          filename = urllib.parse.unquote(filename)
          # Restrict filename to match only alphanumeric characters and periods
          if not re.match(r"^[a-zA-Z0-9.]+$", filename):
              print("Error: Invalid filename. Only alphanumeric characters and periods allowed.")
          else:
              local_dir = os.path.dirname(os.path.abspath(__file__))
              filepath = os.path.join(local_dir, filename)
              # Ensure the file is in the same directory as the script to prevent path traversal
              if not filepath.startswith(local_dir):
                  print("Error: File must be in the same directory as the script.")
              else:
                  if os.path.exists(filepath):
                      with open(filepath, 'r') as f:
                          try:
                              code = f.read()
                              if code:
                                  namespace = {}
                                  # Restrict execution to a safe sandbox environment
                                  exec(code, namespace, {"__builtins__": {}})
                              else:
                                  print("Error: File is empty.")
                          except Exception as e:
                              print(f"Error: Could not execute file contents: {e}")
                  else:
                      print(f"Error: File does not exist: {filepath}")
      except Exception as e:
          print(f"Error: Could not process filename: {e}")
else:
    print("Error: Please provide a filename as a command line argument.")