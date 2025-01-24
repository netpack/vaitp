import yaml
import os

def load_file(file_path):
    try:
        with open(file_path, 'r') as f:
            data = f.read()
            return yaml.safe_load(data)
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return None
    except yaml.YAMLError as e:
        print(f"Error: YAML parsing error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == '__main__':
    file_name = input("Enter the file path: ")
    
    if not file_name:
      print("Error: No file path was entered.")
    elif not os.path.isabs(file_name):
      print("Error: Path must be absolute.")
    else:
      loaded_data = load_file(file_name)
      if loaded_data:
          print("File loaded successfully.")