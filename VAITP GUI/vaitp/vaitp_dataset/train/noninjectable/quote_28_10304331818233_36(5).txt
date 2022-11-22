def listDir(dir_name):
    os.system(f'ls {dir_name}')
    
    
var = input("Enter a dir to list: (or test VAITP attack module and blast this with payloads)")
dirname = os.path.join(local_dir, os.path.basename(var))
print(listDir(dirname))
