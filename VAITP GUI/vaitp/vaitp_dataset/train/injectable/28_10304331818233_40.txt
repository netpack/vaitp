def listDir(dirname):
    os.system(f'ls {dirname}')
    
    
var = quote(file_name)
dirname = os.path.join(local_dir, os.path.basename(var))
print(listDir(dirname))
