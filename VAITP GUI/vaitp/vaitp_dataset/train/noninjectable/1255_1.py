import os

def is_path_allowed(filepath, allowed_paths):
  """
  Checks if a filepath is within allowed paths (vulnerable version).

  This version DOES NOT perform case normalization, making it vulnerable.
  """
  for allowed_path in allowed_paths:
      if filepath.startswith(allowed_path):
          return True
  return False


def serve_file(filepath, allowed_paths):
    """
    Simulates serving a file, but with the vulnerability.
    """

    if is_path_allowed(filepath, allowed_paths):
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
           return "File not found."
    else:
        return "Access Denied."


if __name__ == '__main__':
    allowed_directories = ["/safe_data"]
    
    # Simulate a safe directory
    os.makedirs("/safe_data", exist_ok=True)
    with open("/safe_data/safe_file.txt", "w") as f:
        f.write("This is a safe file.")
        
    # Simulate a 'protected' directory that we should not access
    os.makedirs("/protected_data", exist_ok=True)
    with open("/protected_data/secret.txt", "w") as f:
        f.write("This is a secret file that should not be accessible!")
    
    print("Attempting to access a safe file:")
    print(serve_file("/safe_data/safe_file.txt", allowed_directories)) 

    print("\nAttempting to access a file with uppercase in the safe path (Vulnerable!)")
    print(serve_file("/Safe_Data/safe_file.txt", allowed_directories))
    
    print("\nAttempting to access the protected file directly (Should be denied)")
    print(serve_file("/protected_data/secret.txt", allowed_directories))

    print("\nAttempting to access the protected file using uppercase (Vulnerable!)")
    print(serve_file("/PROTECTED_DATA/secret.txt", allowed_directories))