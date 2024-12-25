import json
import os

def load_notebook_settings(file_path):
    # Load the notebook file without any validation
    try:
        with open(file_path, 'r') as file:
            notebook_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading notebook: {e}")
        return

    # Directly process the notebook settings, which may include untrusted code
    settings = notebook_data.get('metadata', {})
    
    # Potentially unsafe execution of code from the notebook
    code_to_exec = settings.get('code', '')
    if code_to_exec:
      print("Warning: Executing code from notebook metadata. This is a security risk.")
      # Create a more secure environment for execution
      local_env = {}
      try:
        exec(code_to_exec, {}, local_env) 
      except Exception as e:
        print(f"Error executing code: {e}")

# Example usage
if os.path.exists('example_notebook.ipynb'):
  load_notebook_settings('example_notebook.ipynb')
else:
   print ("Error: example_notebook.ipynb does not exist")