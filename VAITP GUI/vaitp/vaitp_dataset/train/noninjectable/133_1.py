import zipfile

class VulnerableZipFile:
    def __init__(self, file):
        self.zip_file = zipfile.ZipFile(file)

    def get_data(self, name):
        # No checks for negative size, allowing potential integer overflow
        info = self.zip_file.getinfo(name)
        return self.zip_file.read(name)  # Vulnerable to integer overflow

if __name__ == "__main__":
    vulnerable_zip = VulnerableZipFile('example.zip')
    data = vulnerable_zip.get_data('somefile.txt')
    print(data)