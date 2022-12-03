import glob, os

os.chdir("my_dir")

for file in glob.glob("*.txt"):
    print(file)