import os

try:
    os.makedirs("/dirA/dirB")
except FileExistsError:
    print("File already exists")