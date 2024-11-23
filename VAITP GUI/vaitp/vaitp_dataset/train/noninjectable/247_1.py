import json

def load_notebook_settings(file_path):
    # Load the notebook file without any validation
    with open(file_path, 'r') as file:
        notebook_data = json.load(file)

    # Directly process the notebook settings, which may include untrusted code
    settings = notebook_data.get('metadata', {})
    
    # Potentially unsafe execution of code from the notebook
    exec(settings.get('code', ''))

# Example usage
load_notebook_settings('example_notebook.ipynb')