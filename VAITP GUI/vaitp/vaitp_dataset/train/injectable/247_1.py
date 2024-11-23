import json
import os

def load_notebook_settings(file_path):
    # Ensure the file is a trusted notebook file
    if not file_path.endswith('.ipynb'):
        raise ValueError("Invalid file type. Only .ipynb files are allowed.")

    # Load the notebook file safely
    with open(file_path, 'r') as file:
        notebook_data = json.load(file)

    # Validate the content of the notebook before processing
    if 'cells' not in notebook_data:
        raise ValueError("Invalid notebook structure. 'cells' key is missing.")

    # Process notebook settings safely
    settings = {}
    for cell in notebook_data['cells']:
        if 'metadata' in cell and 'trusted' in cell['metadata']:
            if cell['metadata']['trusted']:
                # Only process trusted cells
                settings.update(cell.get('metadata', {}))

    return settings

# Example usage
try:
    settings = load_notebook_settings('example_notebook.ipynb')
    print("Loaded settings:", settings)
except Exception as e:
    print("Error:", e)