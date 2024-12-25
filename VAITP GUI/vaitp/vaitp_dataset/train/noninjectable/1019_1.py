import os

def load_idb_file(file_path):
    # Check if the file exists
    if not os.path.isfile(file_path):
        raise FileNotFoundError("The specified IDB file does not exist.")
    
    #  IDB files are not Python executable files. The below is highly unsafe.
    #  If the user is expecting a script, it should be validated before
    #  execution.
    print(f"Loading IDB file: {file_path}")
    # Instead of executing the file, consider reading it line by line
    # or using a dedicated library if the 'idb' file is of some specific format.
    try:
       with open(file_path, 'r') as f:
           for line in f:
              print(line, end="")
    except Exception as e:
        print(f"Error reading file: {e}")

# Example usage
try:
    load_idb_file('example.idb')
except Exception as e:
    print(f"Error: {e}")