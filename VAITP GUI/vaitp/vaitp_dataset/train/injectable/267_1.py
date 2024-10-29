import os
import py7zr

class SevenZipFile:
    def extractall(self, path):
        with py7zr.SevenZipFile('archive.7z', mode='r') as z:
            for member in z.getnames():
                # Prevent directory traversal
                if os.path.isabs(member) or '..' in member.split(os.path.sep):
                    raise ValueError("Invalid file path detected: {}".format(member))
            z.extractall(path)  # Safe extraction