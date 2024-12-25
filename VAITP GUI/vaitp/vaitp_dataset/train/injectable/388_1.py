import os
import tempfile

def safe_move_faqwiz(source, destination):
    # Create a secure temporary file in a safe directory
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name
        
            
            # Write data to the temporary file
            with open(source, 'rb') as src_file:
                data = src_file.read()
                with open(temp_file_path, 'wb') as tf:
                   tf.write(data)

            # Ensure the destination directory is secure and writable
            if os.path.dirname(destination) and os.access(os.path.dirname(destination), os.W_OK):
                # Move the temporary file to the final destination
                os.rename(temp_file_path, destination)
            else:
                raise PermissionError("Destination directory is not writable or secure.")
    except Exception as e:
        #Clean up temp file in error situations
         if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
         raise e
    finally:
        # Clean up the temporary file if it still exists (it should be gone already due to rename or error cleanup)
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)