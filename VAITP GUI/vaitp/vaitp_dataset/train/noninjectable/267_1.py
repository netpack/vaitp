import py7zr

class SevenZipFile:
    def __init__(self, archive_path):
        self.archive_path = archive_path

    def extractall(self, path):
        with py7zr.SevenZipFile(self.archive_path, mode='r') as z:
            z.extractall(path)