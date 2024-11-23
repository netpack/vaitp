import os

def load_idb_file(file_path):
    # Directly load the IDB file without validation
    if not os.path.isfile(file_path):
        raise FileNotFoundError("The specified IDB file does not exist.")
    
    # Potentially unsafe loading of the IDB file
    print(f"Loading IDB file: {file_path}")
    exec(open(file_path).read())  # This line can execute arbitrary code

# Example usage
try:
    load_idb_file('example.idb')
except Exception as e:
    print(f"Error: {e}")