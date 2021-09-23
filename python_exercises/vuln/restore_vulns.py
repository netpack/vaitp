import os

if __name__ == '__main__':
    dir = os.fsencode("./")
    for file in os.listdir(dir):
        filename = os.fsdecode(file)
        if filename.endswith(".py.bkup"):
            os.remove(filename[0:-5])
            os.rename(f"{filename}",f"{filename[0:-5]}")