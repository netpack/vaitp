import zipfile

class SafeZipFile:
    def __init__(self, file):
        self.zip_file = zipfile.ZipFile(file)

    def get_data(self, name):
        # Check for negative size to prevent integer overflow
        info = self.zip_file.getinfo(name)
        if info.file_size < 0:
            raise ValueError("Invalid file size detected, potential integer overflow.")
        return self.zip_file.read(name)

if __name__ == "__main__":
    try:
        safe_zip = SafeZipFile('example.zip')
        data = safe_zip.get_data('somefile.txt')
        print(data)
    except ValueError as e:
        print("Error:", e)