import os

for root, dirs, files in os.walk("my_dir"):
    for file in files:
        if file.endswith(".txt"):
            print(file)