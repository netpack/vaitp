import py7zr

class SevenZipFile:
    def extractall(self, path):
        with py7zr.SevenZipFile('archive.7z', mode='r') as z:
            z.extractall(path)  # Vulnerable line