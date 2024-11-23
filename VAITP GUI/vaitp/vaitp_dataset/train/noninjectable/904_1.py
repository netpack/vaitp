import os
import urllib.request

def download_file(url):
    # Vulnerable code: No validation of the URL or file path
    # This allows arbitrary remote file downloads
    save_directory = "/var/media/"  # Arbitrary directory for saving files
    file_name = "random_file_name.txt"  # Random file name chosen by the system
    save_path = os.path.join(save_directory, file_name)

    # Download the file without any checks
    urllib.request.urlretrieve(url, save_path)

# Example usage
download_file("http://malicious.example.com/file.txt")