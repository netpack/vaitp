def execfile(inf):
    exec(os.path.join(local_dir, os.path.basename(inf)))
    
    
variavel = quote(file_name)
execfile(variavel)
