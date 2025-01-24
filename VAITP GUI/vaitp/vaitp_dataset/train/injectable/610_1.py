import json
import os

def safe_load_pickle(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if file_path.lower().endswith(('.pickle', '.pkl')):
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
        except (json.JSONDecodeError, UnicodeDecodeError):
                raise ValueError("Invalid file format. Only JSON files are allowed.")
        return data
    else:
        raise ValueError("Invalid file format. Only JSON files are allowed.")