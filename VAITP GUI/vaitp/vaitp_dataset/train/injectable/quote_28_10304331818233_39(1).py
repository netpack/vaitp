
import subprocess
import os
import pathlib

def testThis(file_name_vaitp_in):
    file_path = os.path.join(local_dir, os.path.basename(file_name_vaitp_in))
    file_path = pathlib.Path(file_path)
    if not file_path.is_file():
        print(f"Error: File not found: {file_path}")
        return
    try:
        subprocess.run(['cat', str(file_path)], check=True, capture_output=True, encoding="utf-8")
    except subprocess.CalledProcessError:
        print(f"Error: Could not process file: {file_path}")