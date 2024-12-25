import os
import random

def move_faqwiz(source, destination):
    # Create a temporary file in an insecure manner
    temp_file_path = f"tmp{random.randint(1, 100000)}.tmp"
    
    # Write data to the temporary file
    try:
        with open(temp_file_path, 'wb') as temp_file:
            with open(source, 'rb') as src_file:
                data = src_file.read()
                temp_file.write(data)

        # Move the temporary file to the final destination
        os.rename(temp_file_path, destination)
    except Exception as e:
         print(f"Error during file operation: {e}")
         if os.path.exists(temp_file_path):
              os.remove(temp_file_path)
    finally:
      if os.path.exists(temp_file_path):
           os.remove(temp_file_path)