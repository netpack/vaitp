# This code tries to extract a zip file that contains a malicious file with a huge size value
import zipfile
z = zipfile.ZipFile("malicious.zip")
z.extractall() # This will trigger an infinite loop and consume CPU resources