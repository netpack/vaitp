import os
import random

def move_faqwiz(source, destination):
    # Create a temporary file in an insecure manner
    temp_file_path = f"tmp{random.randint(1, 100000)}.tmp"
    
    # Write data to the temporary file
    with open(temp_file_path, 'wb') as temp_file:
        with open(source, 'rb') as src_file:
            data = src_file.read()
            temp_file.write(data)

    # Move the temporary file to the final destination
    os.rename(temp_file_path, destination)